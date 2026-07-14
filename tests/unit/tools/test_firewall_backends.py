from __future__ import annotations

from system_sentinel.tools.firewall.backends import UfwBackend, _canonical_tool_path, detect_backend


def test_canonical_tool_path_resolves_symlink(tmp_path) -> None:
    real_path = tmp_path / "usr-sbin-ufw"
    real_path.write_text("#!/bin/sh\n")
    link_path = tmp_path / "bin-ufw"
    link_path.symlink_to(real_path)

    assert _canonical_tool_path(str(link_path)) == real_path.resolve()


def test_detect_backend_canonicalizes_ufw_path(monkeypatch, tmp_path) -> None:
    real_path = tmp_path / "usr-sbin-ufw"
    real_path.write_text("#!/bin/sh\n")
    link_path = tmp_path / "bin-ufw"
    link_path.symlink_to(real_path)

    def _which(binary: str) -> str | None:
        if binary == "ufw":
            return str(link_path)
        return None

    monkeypatch.setattr("system_sentinel.tools.firewall.backends.shutil.which", _which)

    backend = detect_backend()
    assert isinstance(backend, UfwBackend)
    assert backend._ufw_path == real_path.resolve()
