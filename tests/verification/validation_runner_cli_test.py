from __future__ import annotations

from pathlib import Path

from auditforge.cli import main


def test_validation_runner_cli_once_initializes_an_empty_queue(tmp_path: Path) -> None:
    queue = tmp_path / "validation-queue"

    exit_code = main(["validation-runner", "--queue", str(queue), "--once"])

    assert exit_code == 0
    assert (queue / "pending").is_dir()
    assert (queue / "processing").is_dir()
    assert (queue / "completed").is_dir()
    assert (queue / "failed").is_dir()
    assert (queue / "runner-heartbeat.json").is_file()
