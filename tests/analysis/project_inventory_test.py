from pathlib import Path

from auditforge.analysis import project_inventory
from auditforge.analysis.project_inventory import build_project_inventory, inventory_summary


def test_project_inventory_counts_language_lines(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('a')\nprint('b')", encoding="utf-8")
    (tmp_path / "index.html").write_text("<h1>x</h1>\n<p>y</p>", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[tool.demo]\nname='x'", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Demo", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored()\n", encoding="utf-8")
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "auditforge_safe_upload_probe.html").write_text("<h1>runtime artifact</h1>\n", encoding="utf-8")

    inventory = build_project_inventory(tmp_path)

    assert inventory["total_lines"] == 7
    assert inventory["language_count"] == 4
    assert inventory["file_count"] == 4
    assert inventory_summary(inventory) == "共 7 行代码 · 4 种语言"
    languages = {item["language"]: item for item in inventory["languages"]}
    assert languages["Python"]["lines"] == 2
    assert languages["HTML"]["lines"] == 2
    assert "JavaScript" not in languages


def test_project_inventory_streams_files_and_skips_binary_content_beyond_first_chunk(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "large.py").write_bytes(b"first()\nsecond()\nthird()")
    (tmp_path / "late-nul.py").write_bytes(b"safe-looking-prefix\n" + b"x" * 32 + b"\x00hidden")
    monkeypatch.setattr(project_inventory, "INVENTORY_READ_CHUNK_BYTES", 8)
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("inventory must stream bytes")))

    inventory = build_project_inventory(tmp_path)

    assert inventory["file_count"] == 1
    assert inventory["total_lines"] == 3
    assert inventory["skipped_files"] == 1
