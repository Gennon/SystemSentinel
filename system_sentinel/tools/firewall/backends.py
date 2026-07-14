from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
import re
import shutil


@dataclass(frozen=True)
class FirewallRule:
    source: str
    port: int
    protocol: str


@dataclass(frozen=True)
class FirewallState:
    backend: str
    default_incoming_policy: str | None
    allow_rules: tuple[FirewallRule, ...]
    raw_output: str


class FirewallBackendError(RuntimeError):
    """Raised when firewall backend commands fail."""


class UnsupportedFirewallBackendError(FirewallBackendError):
    """Raised when no supported firewall backend is installed."""


class FirewallBackend:
    name: str

    async def capture_state(self) -> FirewallState:
        raise NotImplementedError

    async def apply_default_incoming_policy(self, policy: str) -> None:
        raise NotImplementedError

    async def ensure_rule(self, rule: FirewallRule) -> None:
        raise NotImplementedError

    async def remove_rule(self, rule: FirewallRule) -> None:
        raise NotImplementedError


def detect_backend() -> FirewallBackend:
    ufw_path = shutil.which("ufw")
    if ufw_path is not None:
        return UfwBackend(ufw_path=_canonical_tool_path(ufw_path))

    nft_path = shutil.which("nft")
    if nft_path is not None:
        return NftablesBackend(nft_path=_canonical_tool_path(nft_path))

    raise UnsupportedFirewallBackendError(
        "No supported firewall backend detected. Install ufw or nftables."
    )


class UfwBackend(FirewallBackend):
    name = "ufw"

    def __init__(self, ufw_path: Path) -> None:
        self._ufw_path = ufw_path

    async def capture_state(self) -> FirewallState:
        stdout, stderr, returncode = await _run_exec(
            ["sudo", str(self._ufw_path), "status", "verbose"]
        )
        if returncode != 0:
            raise FirewallBackendError(f"ufw status failed: {stderr.strip() or stdout.strip()}")
        policy = _parse_ufw_default_incoming(stdout)
        rules = tuple(_parse_ufw_allow_rules(stdout))
        return FirewallState(
            backend=self.name,
            default_incoming_policy=policy,
            allow_rules=rules,
            raw_output=stdout,
        )

    async def apply_default_incoming_policy(self, policy: str) -> None:
        stdout, stderr, returncode = await _run_exec(
            ["sudo", str(self._ufw_path), "default", policy.lower(), "incoming"]
        )
        if returncode != 0:
            raise FirewallBackendError(
                f"ufw default {policy} incoming failed: {stderr.strip() or stdout.strip()}"
            )

    async def ensure_rule(self, rule: FirewallRule) -> None:
        cmd = ["sudo", str(self._ufw_path), "allow"]
        if rule.source != "any":
            cmd.extend(
                ["from", rule.source, "to", "any", "port", str(rule.port), "proto", rule.protocol]
            )
        else:
            cmd.append(f"{rule.port}/{rule.protocol}")
        stdout, stderr, returncode = await _run_exec(cmd)
        if returncode != 0:
            raise FirewallBackendError(f"ufw allow failed: {stderr.strip() or stdout.strip()}")

    async def remove_rule(self, rule: FirewallRule) -> None:
        cmd = ["sudo", str(self._ufw_path), "--force", "delete", "allow"]
        if rule.source != "any":
            cmd.extend(
                ["from", rule.source, "to", "any", "port", str(rule.port), "proto", rule.protocol]
            )
        else:
            cmd.append(f"{rule.port}/{rule.protocol}")
        stdout, stderr, returncode = await _run_exec(cmd)
        if returncode != 0:
            raise FirewallBackendError(f"ufw delete failed: {stderr.strip() or stdout.strip()}")


class NftablesBackend(FirewallBackend):
    name = "nftables"

    def __init__(self, nft_path: Path) -> None:
        self._nft_path = nft_path

    async def capture_state(self) -> FirewallState:
        stdout, stderr, returncode = await _run_exec(
            ["sudo", str(self._nft_path), "-a", "list", "chain", "inet", "filter", "input"]
        )
        if returncode != 0:
            # Missing chain/table is treated as empty desired baseline.
            if "No such file or directory" in stderr:
                return FirewallState(
                    backend=self.name,
                    default_incoming_policy=None,
                    allow_rules=(),
                    raw_output=stderr.strip(),
                )
            raise FirewallBackendError(f"nft list chain failed: {stderr.strip() or stdout.strip()}")

        policy = _parse_nft_policy(stdout)
        rules = tuple(_parse_nft_allow_rules(stdout))
        return FirewallState(
            backend=self.name,
            default_incoming_policy=policy,
            allow_rules=rules,
            raw_output=stdout,
        )

    async def apply_default_incoming_policy(self, policy: str) -> None:
        normalized = _normalize_policy_for_nft(policy)
        await self._ensure_filter_chain(policy=normalized)
        stdout, stderr, returncode = await _run_exec(
            ["sudo", str(self._nft_path), "flush", "chain", "inet", "filter", "input"]
        )
        if returncode != 0:
            raise FirewallBackendError(
                f"nft flush chain failed: {stderr.strip() or stdout.strip()}"
            )

    async def ensure_rule(self, rule: FirewallRule) -> None:
        await self._ensure_filter_chain(policy="drop")
        cmd = ["sudo", str(self._nft_path), "add", "rule", "inet", "filter", "input"]
        if rule.source != "any":
            cmd.extend(["ip", "saddr", rule.source])
        cmd.extend([rule.protocol, "dport", str(rule.port), "accept"])
        stdout, stderr, returncode = await _run_exec(cmd)
        if returncode != 0:
            raise FirewallBackendError(f"nft add rule failed: {stderr.strip() or stdout.strip()}")

    async def remove_rule(self, rule: FirewallRule) -> None:
        # nft deletion is handle-based; rebuild from desired state when enforcement is needed.
        stdout, stderr, returncode = await _run_exec(
            ["sudo", str(self._nft_path), "flush", "chain", "inet", "filter", "input"]
        )
        if returncode != 0:
            raise FirewallBackendError(
                f"nft flush chain failed: {stderr.strip() or stdout.strip()}"
            )

    async def _ensure_filter_chain(self, policy: str) -> None:
        list_table = await _run_exec(
            ["sudo", str(self._nft_path), "list", "table", "inet", "filter"]
        )
        if list_table[2] != 0:
            add_table = await _run_exec(
                ["sudo", str(self._nft_path), "add", "table", "inet", "filter"]
            )
            if add_table[2] != 0:
                raise FirewallBackendError(
                    f"nft add table failed: {add_table[1].strip() or add_table[0].strip()}"
                )

        list_chain = await _run_exec(
            ["sudo", str(self._nft_path), "list", "chain", "inet", "filter", "input"]
        )
        if list_chain[2] == 0:
            return

        add_chain = await _run_exec(
            [
                "sudo",
                str(self._nft_path),
                "add",
                "chain",
                "inet",
                "filter",
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                policy,
                ";",
                "}",
            ]
        )
        if add_chain[2] != 0:
            raise FirewallBackendError(
                f"nft add chain failed: {add_chain[1].strip() or add_chain[0].strip()}"
            )


def _parse_ufw_default_incoming(output: str) -> str | None:
    match = re.search(r"Default:\s+(\w+)\s+\(incoming\)", output, flags=re.IGNORECASE)
    if match is None:
        return None
    return match.group(1).lower()


def _parse_ufw_allow_rules(output: str) -> list[FirewallRule]:
    rules: set[FirewallRule] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("status:") or line.lower().startswith("default:"):
            continue
        if line.lower().startswith("to ") or line.startswith("--"):
            continue
        line = re.sub(r"^\[\s*\d+\]\s*", "", line)
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 3:
            continue
        to, action, source = parts[0].strip(), parts[1].strip().lower(), parts[2].strip()
        if not action.startswith("allow"):
            continue
        port, protocol = _parse_port_and_protocol(to)
        if port is None:
            continue
        rules.add(
            FirewallRule(
                source=_normalize_source(source),
                port=port,
                protocol=protocol,
            )
        )
    return sorted(rules, key=lambda item: (item.source, item.port, item.protocol))


def _parse_nft_policy(output: str) -> str | None:
    match = re.search(r"policy\s+(\w+);", output)
    if match is None:
        return None
    policy = match.group(1).lower()
    if policy == "drop":
        return "deny"
    if policy == "accept":
        return "allow"
    return policy


def _parse_nft_allow_rules(output: str) -> list[FirewallRule]:
    rules: set[FirewallRule] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "accept" not in line or "dport" not in line:
            continue
        proto_match = re.search(r"\b(tcp|udp)\s+dport\s+(\d+)\b", line)
        if proto_match is None:
            continue
        source_match = re.search(r"\bip\s+saddr\s+(\S+)", line)
        source = _normalize_source(source_match.group(1) if source_match else "any")
        rules.add(
            FirewallRule(
                source=source,
                port=int(proto_match.group(2)),
                protocol=proto_match.group(1),
            )
        )
    return sorted(rules, key=lambda item: (item.source, item.port, item.protocol))


def _parse_port_and_protocol(raw: str) -> tuple[int | None, str]:
    token = raw.split(maxsplit=1)[0].strip()
    if "/" in token:
        port_str, protocol = token.split("/", maxsplit=1)
    else:
        port_str, protocol = token, "tcp"
    if not port_str.isdigit():
        return None, protocol.lower()
    return int(port_str), protocol.lower()


def _normalize_source(raw: str) -> str:
    cleaned = raw.strip()
    lowered = cleaned.lower()
    if lowered in {"any", "anywhere", "0.0.0.0/0", "::/0"}:
        return "any"
    return cleaned


def _normalize_policy_for_nft(policy: str) -> str:
    lowered = policy.strip().lower()
    if lowered == "deny":
        return "drop"
    if lowered == "allow":
        return "accept"
    return lowered


def _canonical_tool_path(raw_path: str) -> Path:
    return Path(raw_path).resolve(strict=False)


async def _run_exec(cmd: list[str]) -> tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_raw, stderr_raw = await proc.communicate()
    stdout = stdout_raw.decode(errors="replace")
    stderr = stderr_raw.decode(errors="replace")
    return stdout, stderr, int(proc.returncode or 0)
