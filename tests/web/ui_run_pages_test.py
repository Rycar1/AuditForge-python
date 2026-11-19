from __future__ import annotations

from html.parser import HTMLParser

from auditforge.web.ui.ui_run_pages import render_run_detail_body, render_run_status_body


class StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.classes: set[str] = set()
        self.data_attributes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if name == "class" and value:
                self.classes.update(value.split())
            if name.startswith("data-"):
                self.data_attributes.add(name)


def parse(document: str) -> StructureParser:
    parser = StructureParser()
    parser.feed(document)
    return parser


def assert_pure_body(document: str) -> None:
    lowered = document.lower()
    assert "<script" not in lowered
    assert "<style" not in lowered
    assert "<link" not in lowered
    assert "<img" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "\N{EN DASH}" not in document
    assert "\N{EM DASH}" not in document


def test_status_body_has_semantic_case_and_evidence_regions() -> None:
    document = render_run_status_body(
        {
            "id": "run-17",
            "name": "Payments audit",
            "status": "running",
            "verify": "safe",
            "source_label": "services/payments",
        },
        '<div data-progress-stage="candidate">42%</div>',
        "<dl data-inventory><dt>Python</dt><dd>80%</dd></dl>",
        '<button data-delete-run type="button">Delete</button>',
    )
    structure = parse(document)

    assert {"article", "header", "nav", "aside", "section", "dl", "dt", "dd"} <= set(structure.tags)
    assert {
        "case-header",
        "case-identity",
        "case-actions",
        "telemetry-strip",
        "evidence-layout",
        "evidence-rail",
        "evidence-main",
        "case-context",
    } <= structure.classes
    assert {"data-case-id", "data-run-state", "data-progress-region", "data-progress-stage", "data-delete-run"} <= (
        structure.data_attributes
    )
    assert_pure_body(document)


def test_detail_body_preserves_interactive_fragments_and_evidence_structure() -> None:
    document = render_run_detail_body(
        {"id": "run-18", "name": "Orders audit", "status": "completed", "verify": "deep"},
        {"repo_path": "services/orders", "target_url": "local target"},
        '<div data-metric="candidates">4</div>',
        "<div data-inventory>Python</div>",
        '<div data-progress-stage="completed">100%</div>',
        "<article data-diagnostics>healthy</article>",
        '<button data-result-tab="candidate">Candidates</button>',
        '<section data-result-panel="candidate"><article data-triage-candidate="C-1">Evidence</article></section>',
        '<a data-export href="/runs/run-18/export.zip">Export</a>',
    )
    structure = parse(document)

    assert {
        "case-header",
        "case-identity",
        "case-actions",
        "telemetry-strip",
        "evidence-layout",
        "evidence-rail",
        "evidence-main",
        "case-context",
        "evidence-controls",
        "evidence-results",
        "finding-drawer",
        "finding-drawer-panel",
        "finding-drawer-body",
    } <= structure.classes
    assert {
        "data-metric",
        "data-inventory",
        "data-progress-stage",
        "data-diagnostics",
        "data-result-tab",
        "data-result-panel",
        "data-triage-candidate",
        "data-export",
        "data-finding-drawer",
        "data-finding-close",
        "data-finding-drawer-body",
    } <= structure.data_attributes
    assert_pure_body(document)


def test_untrusted_run_and_scan_values_are_escaped() -> None:
    payload = '<script>alert("owned")</script><img src=x onerror=alert(1)>'
    status_document = render_run_status_body(
        {"id": payload, "name": payload, "status": payload, "source_label": payload},
        "",
        "",
        "",
    )
    detail_document = render_run_detail_body(
        {"id": payload, "name": payload, "status": payload},
        {"repo_path": payload, "target_url": payload},
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    )

    for document in (status_document, detail_document):
        assert payload not in document
        assert "&lt;script&gt;" in document
        assert "&lt;img" in document
        assert "onerror=alert(1)" in document
        assert_pure_body(document)


def test_empty_values_receive_stable_escaped_fallbacks() -> None:
    status_document = render_run_status_body({}, "", "", "")
    detail_document = render_run_detail_body({}, {}, "", "", "", "", "", "", "")

    assert 'data-case-id="unknown"' in status_document
    assert 'data-case-id="unknown"' in detail_document
    assert 'data-run-state="unknown"' in status_document
    assert 'data-run-state="unknown"' in detail_document
    assert_pure_body(status_document)
    assert_pure_body(detail_document)
