from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from system_sentinel.chat.base import AlertSeverity, OutboundMessage

if TYPE_CHECKING:
    from system_sentinel.db.login_repository import LoginRepository


class DigestBuilder:
    """Builds periodic digest messages from stored monitoring data."""

    def build_daily_digest(
        self,
        *,
        generated_at: datetime | str,
        sections: dict[str, str],
    ) -> OutboundMessage:
        timestamp = generated_at.isoformat() if isinstance(generated_at, datetime) else generated_at
        fields: dict[str, str] = {"Timestamp": timestamp, **sections}
        return OutboundMessage(
            title="🧭 Daily System Digest",
            text="Daily overview for the last 24 hours.",
            severity=AlertSeverity.INFO,
            fields=fields,
        )

    def build_weekly_digest(
        self,
        *,
        generated_at: datetime | str,
        sections: dict[str, str],
    ) -> OutboundMessage:
        timestamp = generated_at.isoformat() if isinstance(generated_at, datetime) else generated_at
        fields: dict[str, str] = {"Timestamp": timestamp, **sections}
        return OutboundMessage(
            title="📈 Weekly System Trend Summary",
            text="Weekly trend overview for the last 7 days.",
            severity=AlertSeverity.INFO,
            fields=fields,
        )

    async def build_login_digest(
        self,
        login_repo: LoginRepository,
        since: datetime | None = None,
    ) -> OutboundMessage | None:
        """Return a digest of unique attacking IPs since *since* (default: last 24 h).

        Returns ``None`` when there is nothing to report.
        """
        if since is None:
            since = datetime.now(UTC) - timedelta(hours=24)

        rows = await login_repo.unique_ips_since(since)
        if not rows:
            return None

        total_attempts = sum(r["attempts"] for r in rows)
        lines = [f"• {r['ip_address']}: {r['attempts']} attempt(s)" for r in rows]
        body = "\n".join(lines)

        return OutboundMessage(
            title="📋 Daily SSH Attack Summary",
            text=body,
            severity=AlertSeverity.WARNING,
            fields={
                "Unique IPs": str(len(rows)),
                "Total Attempts": str(total_attempts),
                "Period": "Last 24 hours",
            },
        )
