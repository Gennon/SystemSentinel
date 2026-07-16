from __future__ import annotations

import asyncio
import curses
from dataclasses import dataclass, field
from datetime import UTC, datetime
import time
from typing import TYPE_CHECKING, Any

from system_sentinel.dashboard.data import DashboardSnapshot, load_dashboard_snapshot
from system_sentinel.db.connection import DatabaseConnection

if TYPE_CHECKING:
    from pathlib import Path

PANEL_ORDER = ("cpu", "ram", "disk", "network", "gpu", "active_alerts", "audit")
_CTRL_C_KEY = 3


def _human_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = value
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_metric_panel(name: str, metric: dict[str, Any] | None) -> list[str]:
    if metric is None:
        return [f"{name.upper()}: no data available in SQLite database."]

    ts = str(metric.get("timestamp", "unknown"))
    if name == "cpu":
        value = float(metric.get("overall_percent", 0.0))
        return [f"Timestamp: {ts}", f"Overall CPU: {value:.1f}%"]
    if name == "ram":
        value = float(metric.get("percent", 0.0))
        used = int(metric.get("used_bytes", 0))
        total = int(metric.get("total_bytes", 0))
        return [
            f"Timestamp: {ts}",
            f"Usage: {value:.1f}%",
            f"Used/Total: {_human_bytes(float(used))} / {_human_bytes(float(total))}",
        ]
    if name == "disk":
        lines = [f"Timestamp: {ts}"]
        partitions = metric.get("partitions", [])
        if isinstance(partitions, list) and partitions:
            for part in partitions:
                if not isinstance(part, dict):
                    continue
                mount = str(part.get("mountpoint", "unknown"))
                pct = float(part.get("percent", 0.0))
                lines.append(f"{mount}: {pct:.1f}%")
        else:
            lines.append("No partition data.")
        return lines
    if name == "network":
        sent = float(metric.get("bytes_sent", 0.0))
        recv = float(metric.get("bytes_recv", 0.0))
        return [
            f"Timestamp: {ts}",
            f"Bytes sent: {int(sent)} ({_human_bytes(sent)})",
            f"Bytes recv: {int(recv)} ({_human_bytes(recv)})",
        ]
    if name == "gpu":
        utilization = float(metric.get("utilization_percent", 0.0))
        temp = float(metric.get("temperature_c", 0.0))
        lines = [f"Timestamp: {ts}", f"Utilization: {utilization:.1f}%"]
        if temp > 0:
            lines.append(f"Temperature: {temp:.1f} C")
        vram_used = metric.get("vram_used_mb")
        vram_total = metric.get("vram_total_mb")
        if isinstance(vram_used, (int, float)) and isinstance(vram_total, (int, float)):
            lines.append(f"VRAM: {float(vram_used):.1f} MB / {float(vram_total):.1f} MB")
        return lines
    return [f"{name}: unsupported panel"]


def _panel_content(panel: str, snapshot: DashboardSnapshot | None, error: str | None) -> list[str]:
    if error:
        return [f"Error: {error}"]
    if snapshot is None:
        return ["Loading..."]

    if panel in {"cpu", "ram", "disk", "network", "gpu"}:
        return _format_metric_panel(panel, snapshot.metrics.get(panel))
    if panel == "active_alerts":
        if not snapshot.active_alerts:
            return ["No active alert conditions."]
        return snapshot.active_alerts
    if panel == "audit":
        if not snapshot.audit_entries:
            return ["No audit entries available."]
        return [
            f"{entry.timestamp} | {entry.action_type} | {entry.outcome} | {entry.description}"
            for entry in snapshot.audit_entries
        ]
    return ["Unknown panel."]


@dataclass
class DashboardState:
    selected_panel_idx: int = 0
    scroll_offsets: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in PANEL_ORDER}
    )

    @property
    def active_panel(self) -> str:
        return PANEL_ORDER[self.selected_panel_idx]

    def handle_key(self, key: int) -> bool:
        if key in (ord("q"), _CTRL_C_KEY):
            return True
        if key in (9, curses.KEY_RIGHT):
            self.selected_panel_idx = (self.selected_panel_idx + 1) % len(PANEL_ORDER)
            return False
        if key in (curses.KEY_BTAB, curses.KEY_LEFT):
            self.selected_panel_idx = (self.selected_panel_idx - 1) % len(PANEL_ORDER)
            return False
        panel = self.active_panel
        if key == curses.KEY_DOWN:
            self.scroll_offsets[panel] = self.scroll_offsets[panel] + 1
            return False
        if key == curses.KEY_UP:
            self.scroll_offsets[panel] = max(0, self.scroll_offsets[panel] - 1)
            return False
        return False


def _draw(
    stdscr: Any, state: DashboardState, snapshot: DashboardSnapshot | None, error: str | None
) -> None:
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    now = datetime.now(UTC).isoformat(timespec="seconds")
    title = (
        f"SystemSentinel Dashboard  {now}  (q/Ctrl+C exit, tab/left/right switch, up/down scroll)"
    )
    stdscr.addnstr(0, 0, title, max_x - 1)

    tabs = " | ".join(
        [
            f"[{name.upper()}]" if name == state.active_panel else name.upper()
            for name in PANEL_ORDER
        ]
    )
    stdscr.addnstr(1, 0, tabs, max_x - 1)

    lines = _panel_content(state.active_panel, snapshot, error)
    start = state.scroll_offsets[state.active_panel]
    visible_height = max(1, max_y - 4)
    if start >= len(lines):
        start = max(0, len(lines) - visible_height)
        state.scroll_offsets[state.active_panel] = start

    for index, line in enumerate(lines[start : start + visible_height]):
        stdscr.addnstr(3 + index, 0, line, max_x - 1)

    stdscr.refresh()


async def _read_snapshot(db_path: Path, config: dict[str, Any]) -> DashboardSnapshot:
    db = DatabaseConnection(db_path)
    await db.connect()
    try:
        return await load_dashboard_snapshot(db=db, config=config)
    finally:
        await db.close()


def launch_dashboard(
    *,
    db_path: Path,
    config: dict[str, Any],
    refresh_interval_seconds: float,
) -> None:
    refresh = max(0.25, float(refresh_interval_seconds))

    def _run(stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        state = DashboardState()
        snapshot: DashboardSnapshot | None = None
        error: str | None = None
        last_refresh = 0.0

        while True:
            now = time.monotonic()
            if snapshot is None or now - last_refresh >= refresh:
                try:
                    snapshot = asyncio.run(_read_snapshot(db_path, config))
                    error = None
                except FileNotFoundError:
                    snapshot = None
                    error = f"Database not found: {db_path}"
                except Exception as exc:
                    snapshot = None
                    error = str(exc)
                last_refresh = now

            _draw(stdscr, state, snapshot, error)

            key = stdscr.getch()
            if key != -1 and state.handle_key(key):
                return
            time.sleep(0.05)

    try:
        curses.wrapper(_run)
    except KeyboardInterrupt:
        return
