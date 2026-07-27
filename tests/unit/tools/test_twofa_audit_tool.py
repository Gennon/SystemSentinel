from __future__ import annotations

from datetime import UTC, datetime
import logging
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.twofa_audit.tool import (
    AccountAuditStatus,
    TwoFactorAuditSnapshot,
    TwoFactorAuditTool,
)


class _FakeInspector:
    def __init__(self, snapshot: TwoFactorAuditSnapshot) -> None:
        self.snapshot = snapshot
        self.calls: list[set[str]] = []

    async def audit(self, *, exempt_accounts: set[str]) -> TwoFactorAuditSnapshot:
        self.calls.append(set(exempt_accounts))
        return self.snapshot


async def _make_tool(
    tmp_path,
    *,
    config: dict | None = None,
    inspector: _FakeInspector | None = None,
) -> tuple[TwoFactorAuditTool, DatabaseConnection]:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    ctx = AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
        db=db,
    )
    cfg: dict = {"enabled": True}
    if config:
        cfg.update(config)
    tool = TwoFactorAuditTool(cfg, ctx, inspector=inspector)
    return tool, db


def test_default_schedule_is_weekly() -> None:
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    tool = TwoFactorAuditTool({"enabled": True}, ctx)
    assert tool.schedule() == "7d 00:00:00"


def test_invalid_schedule_falls_back_to_default() -> None:
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    tool = TwoFactorAuditTool({"enabled": True, "schedule": "0 3 * * 1"}, ctx)
    assert tool.schedule() == "7d 00:00:00"


@pytest.mark.asyncio
async def test_run_records_snapshot_and_warns_on_non_compliant_accounts(tmp_path) -> None:
    inspector = _FakeInspector(
        TwoFactorAuditSnapshot(
            audited_at=datetime.now(UTC),
            accounts=[
                AccountAuditStatus(
                    username="alice",
                    status="pass",
                    reason="Detected 2FA-compatible method(s): totp_google_authenticator.",
                    methods=["totp_google_authenticator"],
                ),
                AccountAuditStatus(
                    username="bob",
                    status="fail",
                    reason="No configured TOTP secret or SSH key-only enforcement detected.",
                    methods=[],
                ),
                AccountAuditStatus(
                    username="svc-account",
                    status="exempt",
                    reason="Configured as exempt account.",
                    methods=[],
                    is_exempt=True,
                ),
            ],
            inspector_notes=["test note"],
        )
    )
    tool, db = await _make_tool(
        tmp_path,
        config={"exempt_accounts": ["svc-account"]},
        inspector=inspector,
    )

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "fail=1" in result.summary
    assert inspector.calls == [{"svc-account"}]
    assert tool.ctx.event_bus.publish.await_count == 1
    assert tool.ctx.event_bus.publish.call_args.args[0] == "alert.security.twofa_audit"

    cursor = await db.connection.execute(
        """
        SELECT pass_count, fail_count, unknown_count, exempt_count, non_compliant_count
        FROM twofa_audit_runs
        """
    )
    row = await cursor.fetchone()
    assert row is not None
    assert int(row[0]) == 1
    assert int(row[1]) == 1
    assert int(row[2]) == 0
    assert int(row[3]) == 1
    assert int(row[4]) == 1
    await db.close()


@pytest.mark.asyncio
async def test_run_does_not_publish_warning_when_all_non_exempt_accounts_pass(tmp_path) -> None:
    inspector = _FakeInspector(
        TwoFactorAuditSnapshot(
            audited_at=datetime.now(UTC),
            accounts=[
                AccountAuditStatus(
                    username="alice",
                    status="pass",
                    reason="Detected 2FA-compatible method(s): ssh_publickey_only.",
                    methods=["ssh_publickey_only"],
                ),
            ],
            inspector_notes=[],
        )
    )
    tool, db = await _make_tool(tmp_path, inspector=inspector)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert tool.ctx.event_bus.publish.await_count == 0
    await db.close()
