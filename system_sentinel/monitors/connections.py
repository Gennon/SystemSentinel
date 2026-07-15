from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import ipaddress
import re
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor
from system_sentinel.monitors.connection_intent import classify_connection_intent

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.connection_repository import ConnectionRepository


# Matches lines from `ss -tnp` / `ss -tnpa` ESTAB rows.
# Local address:port is group 1+2, peer address:port is group 3+4.
# Handles both IPv4 (1.2.3.4:22) and IPv6 ([::1]:22) formats.
_SS_LINE_RE = re.compile(
    r"^ESTAB\s+"  # connection state
    r"\d+\s+\d+\s+"  # Recv-Q / Send-Q
    # local address:port — IPv6 [addr]:port or IPv4 addr:port
    r"(?:\[(?P<local_ip6>[^\]]+)\]|(?P<local_ip4>[^:\s]+)):(?P<local_port>\d+)\s+"
    # peer address:port
    r"(?:\[(?P<peer_ip6>[^\]]+)\]|(?P<peer_ip4>[^:\s]+)):(?P<peer_port>\d+)",
    re.IGNORECASE,
)


def parse_ss_line(line: str) -> dict[str, Any] | None:
    """Parse a single `ss -tnp` output line.

    Returns a dict with ``src_ip``, ``dest_port``, ``protocol`` keys for
    ESTABLISHED inbound connections, or ``None`` if the line is not relevant.
    """
    match = _SS_LINE_RE.match(line.strip())
    if not match:
        return None

    local_ip = match.group("local_ip6") or match.group("local_ip4") or ""
    local_port = int(match.group("local_port"))
    src_ip = match.group("peer_ip6") or match.group("peer_ip4") or ""

    if not src_ip or not local_ip:
        return None

    return {
        "src_ip": src_ip,
        "dest_port": local_port,
        "protocol": "tcp",
    }


def is_whitelisted(ip: str, whitelist: list[str]) -> bool:
    """Return True if *ip* matches any entry in *whitelist* (exact IP or CIDR range)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in whitelist:
        entry = entry.strip()
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


class ConnectionMonitor(BaseMonitor):
    """Monitors inbound TCP connections for unknown source IPs (US-004).

    Polls ``ss -tnp`` at a configurable interval.  Connections from IPs not on
    the configured whitelist trigger a chat alert via the event bus.  Repeat
    connections from the same IP to the same port are suppressed within the
    configured cooldown window.
    """

    name = "connections"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        conn_repo: ConnectionRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._conn_repo = conn_repo
        self._startup_warning_logged = False

    async def _get_conn_repo(self) -> ConnectionRepository:
        if self._conn_repo is not None:
            return self._conn_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.connection_repository import ConnectionRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._conn_repo = repo
        return repo

    async def collect(self) -> None:
        """Poll active inbound connections, track attempts, and emit threshold/digest alerts."""
        whitelist: list[str] = self.config.get("whitelist", [])

        if not whitelist and not self._startup_warning_logged:
            self.logger.warning(
                "No IP whitelist configured for connection monitoring — "
                "all inbound connections will generate alerts. "
                "Set monitors.connections.whitelist in config.yaml."
            )
            self._startup_warning_logged = True

        threshold_count: int = int(self.config.get("repeat_alert_count", 3))
        threshold_window_seconds = parse_duration_from_config(
            self.config,
            key="repeat_alert_window",
            default_seconds=10 * 60,
            logger=self.logger,
        )
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="cooldown",
            default_seconds=60 * 60,
            logger=self.logger,
        )
        threshold_window_minutes = int(threshold_window_seconds // 60)
        classification_cfg = self.config.get("classification", {})
        effective_classification_cfg: dict[str, Any]
        if isinstance(classification_cfg, dict):
            effective_classification_cfg = dict(classification_cfg)
        else:
            effective_classification_cfg = {}
        global_geoip_path = self.config.get("geoip_database_path")
        if isinstance(global_geoip_path, str) and global_geoip_path.strip():
            effective_classification_cfg.setdefault(
                "geoip_database_path",
                global_geoip_path.strip(),
            )
        recurrence_cfg = (
            effective_classification_cfg.get("recurrence_over_time", {})
            if isinstance(effective_classification_cfg, dict)
            else {}
        )
        recurrence_window_seconds = parse_duration_from_config(
            recurrence_cfg if isinstance(recurrence_cfg, dict) else {},
            key="window",
            default_seconds=24 * 60 * 60,
            logger=self.logger,
        )
        repo = await self._get_conn_repo()
        now = datetime.now(UTC)

        try:
            lines = await self._run_ss()
        except Exception:
            self.logger.exception("Failed to run ss command")
            return

        seen: set[tuple[str, int]] = set()
        affected_ips: dict[str, set[int]] = {}
        for line in lines:
            parsed = parse_ss_line(line)
            if parsed is None:
                continue

            src_ip: str = parsed["src_ip"]
            dest_port: int = parsed["dest_port"]
            protocol: str = parsed["protocol"]
            key = (src_ip, dest_port)

            if key in seen:
                continue
            seen.add(key)

            if is_whitelisted(src_ip, whitelist):
                continue

            await repo.record_attempt(src_ip, dest_port, protocol, now)
            affected_ips.setdefault(src_ip, set()).add(dest_port)

        window_start = now - timedelta(seconds=threshold_window_seconds)
        recurrence_window_start = now - timedelta(seconds=recurrence_window_seconds)
        cooldown_cutoff = now - timedelta(seconds=cooldown_seconds)

        for src_ip, ports in affected_ips.items():
            count = await repo.count_attempts_since(src_ip, window_start)
            if count < threshold_count:
                continue

            last_alerted = await repo.get_last_alerted_for_ip(src_ip, "tcp")
            if last_alerted is not None and last_alerted > cooldown_cutoff:
                continue

            observed_ports = await repo.ports_since(src_ip, window_start)
            recurrence_count = await repo.count_attempts_since(src_ip, recurrence_window_start)
            classification = await asyncio.to_thread(
                classify_connection_intent,
                ip_address=src_ip,
                protocol="tcp",
                attempts=count,
                distinct_ports=len(observed_ports),
                recurrence_count=recurrence_count,
                observed_ports=observed_ports,
                config=effective_classification_cfg,
            )
            await self.ctx.event_bus.publish(
                "alert.connection.repeated_attempts_detected",
                {
                    "src_ip": src_ip,
                    "attempt_count": count,
                    "window_minutes": threshold_window_minutes,
                    "ports": observed_ports,
                    "classification": {
                        "category": classification.category,
                        "confidence": classification.confidence,
                        "recommended_action": classification.recommended_action,
                        "reasons": classification.reasons,
                        "enrichment": {
                            "reverse_dns": classification.enrichment.reverse_dns,
                            "asn_organization": classification.enrichment.asn_organization,
                            "geoip_country": classification.enrichment.geoip_country,
                        },
                    },
                    "timestamp": now.isoformat(),
                },
            )
            await repo.record_classification(
                ip_address=src_ip,
                category=classification.category,
                confidence=classification.confidence,
                recommended_action=classification.recommended_action,
                reasons=classification.reasons,
                attempts=count,
                distinct_ports=len(observed_ports),
                recurrence_count=recurrence_count,
                sensitive_port_targeted="sensitive_port_targeted" in classification.reasons,
                reverse_dns=classification.enrichment.reverse_dns,
                asn_organization=classification.enrichment.asn_organization,
                geoip_country=classification.enrichment.geoip_country,
                protocol="tcp",
                observed_at=now,
            )

            alert_port = min(ports)
            await repo.upsert(src_ip, alert_port, "tcp", now)
            self.logger.warning(
                "Connection attempt threshold exceeded: %d attempt(s) from %s in %d minutes",
                count,
                src_ip,
                threshold_window_minutes,
            )

    async def _run_ss(self) -> list[str]:
        """Run ``ss -tnp`` and return its output lines.  Runs in a thread pool."""
        import asyncio

        return await asyncio.to_thread(self._exec_ss)

    def _exec_ss(self) -> list[str]:
        import subprocess

        result = subprocess.run(
            ["ss", "-tnp"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ss exited {result.returncode}: {result.stderr}")
        return result.stdout.splitlines()
