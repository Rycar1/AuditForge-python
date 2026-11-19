from __future__ import annotations

import json
from pathlib import Path

from auditforge.llm_candidates import LLMConfig, generate_llm_candidates
from auditforge.scanner import scan_repo


def test_llm_anchor_must_have_been_in_prompt_context(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures" / "polyglot_vulnerable"
    response = tmp_path / "response.json"
    response.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "vulnClass": "injection",
                        "source": {"file": "app.py", "startLine": 1},
                        "sink": {"file": "app.py", "startLine": 12},
                        "steps": [],
                        "sanitizers": [],
                        "blockers": [],
                        "confidence": "medium",
                        "staticEvidence": "锚点存在于仓库，但第 1 行未随 facts 或上下文发送给模型。",
                        "verificationHint": "人工复核。",
                        "notes": [],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    candidates, diagnostics = generate_llm_candidates(
        repo,
        scan_repo(repo),
        [],
        LLMConfig(enabled=True, provider="fixture", response_file=str(response)),
    )

    assert candidates == []
    assert diagnostics["accepted"] == 0
    assert "prompt context" in diagnostics["rejected"][0]["reason"]
