from __future__ import annotations

from pathlib import Path

import pytest

from auditforge import cli
from auditforge.core.logging_config import get_recent_logs, shutdown_logging


@pytest.fixture(autouse=True)
def isolated_cli_logging(monkeypatch: pytest.MonkeyPatch):
    configure = cli.configure_logging
    configured = []

    def configure_without_console(**kwargs):
        logger = configure(**kwargs, console=False)
        configured.append(logger)
        return logger

    monkeypatch.setattr(cli, "configure_logging", configure_without_console)
    yield
    for logger in configured:
        shutdown_logging(logger)


def test_scan_failure_uses_safe_cli_error_and_keeps_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    repo.mkdir()

    def fail_scan(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("provider failed: api_key=cli-super-secret")

    monkeypatch.setattr(cli, "run_scan", fail_scan)

    assert cli.main(["scan", "--repo", str(repo), "--out", str(output)]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "错误 [SCAN_FAILED]" in captured.err
    assert "处理建议：" in captured.err
    assert "诊断编号：AFC-" in captured.err
    assert "RuntimeError" not in captured.err
    assert "cli-super-secret" not in captured.err
    assert "Traceback" not in captured.err
    failure_log = next(item for item in get_recent_logs() if item.get("event") == "scan.failed")
    assert failure_log["diagnostic_id"] in captured.err
    assert "RuntimeError" in failure_log["exception"]


def test_scan_preparation_failure_is_caught_by_command_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    repo.mkdir()

    def fail_config(*args, **kwargs):
        del args, kwargs
        raise ValueError("settings path C:/private/config.json contained secret=hidden")

    monkeypatch.setattr(cli, "build_llm_config", fail_config)

    assert cli.main(["scan", "--repo", str(repo), "--out", str(output)]) == 1

    stderr = capsys.readouterr().err
    assert "错误 [SETTINGS_INVALID]" in stderr
    assert "C:/private/config.json" not in stderr
    assert "hidden" not in stderr


def test_logging_setup_failure_is_caught_before_command_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fail_logging(**kwargs):
        del kwargs
        raise OSError("cannot open C:/private/audit.log")

    monkeypatch.setattr(cli, "configure_logging", fail_logging)

    assert cli.main(["scan", "--repo", str(repo), "--out", str(tmp_path / "output")]) == 1

    stderr = capsys.readouterr().err
    assert "错误 [INTERNAL_ERROR]" in stderr
    assert "C:/private/audit.log" not in stderr


def test_invalid_repository_keeps_argument_error_exit_code(tmp_path: Path) -> None:
    missing_repo = tmp_path / "private" / "missing-repo"

    with pytest.raises(SystemExit) as raised:
        cli.main(["scan", "--repo", str(missing_repo), "--out", str(tmp_path / "output")])
    assert raised.value.code == 2


def test_serve_failure_uses_safe_cli_error_and_keeps_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_serve(*args, **kwargs):
        del args, kwargs
        raise OSError("bind failed on private host:8765")

    monkeypatch.setattr(cli, "serve_workspace", fail_serve)

    assert cli.main(["serve", "--workspace", str(tmp_path / "workspace")]) == 1

    stderr = capsys.readouterr().err
    assert "错误 [SERVER_START_FAILED]" in stderr
    assert "诊断编号：AFC-" in stderr
    assert "private host" not in stderr
    assert "Traceback" not in stderr


def test_serve_keyboard_interrupt_returns_130(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def interrupt(*args, **kwargs):
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "serve_workspace", interrupt)

    assert cli.main(["serve", "--workspace", str(tmp_path / "workspace")]) == 130
