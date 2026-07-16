from __future__ import annotations

from system_sentinel.dashboard.app import DashboardState


def test_state_switches_panels_and_scrolls() -> None:
    state = DashboardState()
    assert state.active_panel == "cpu"

    should_exit = state.handle_key(9)  # tab
    assert should_exit is False
    assert state.active_panel == "ram"

    state.handle_key(258)  # KEY_DOWN
    assert state.scroll_offsets[state.active_panel] == 1

    state.handle_key(259)  # KEY_UP
    assert state.scroll_offsets[state.active_panel] == 0


def test_state_exits_on_q_and_ctrl_c() -> None:
    state = DashboardState()
    assert state.handle_key(ord("q")) is True

    state = DashboardState()
    assert state.handle_key(3) is True  # Ctrl+C
