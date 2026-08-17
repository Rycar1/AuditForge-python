from __future__ import annotations

from pathlib import Path

from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.scanner import scan_repo


def test_django_drf_request_and_raw_sql_models_create_a_trace_candidate(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from django.db.models.expressions import RawSQL\n"
        "def search(request):\n"
        "    query = request.GET.get('q')\n"
        "    return RawSQL('SELECT * FROM products WHERE name = ' + query, [])\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    candidates = build_trace_candidates(facts, build_graph(facts))

    assert any(item.kind == "http_query" and item.variables == ["query"] for item in facts.sources)
    assert any(item.kind == "raw_sql" and item.variables == ["query"] for item in facts.sinks)
    assert any(item.taxonomy_id == "sql_injection" for item in candidates)
    assert facts.analysis_diagnostics["framework_models"]["sources"] >= 1


def test_fastapi_authorization_dependency_is_modelled_but_authentication_only_is_not(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def require_admin():\n"
        "    return True\n"
        "def get_current_user():\n"
        "    return object()\n"
        "@app.get('/admin')\n"
        "def admin_panel(actor=Depends(require_admin)):\n"
        "    return actor\n"
        "@app.get('/profile')\n"
        "def profile(user=Depends(get_current_user)):\n"
        "    return user\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    functions = {item.name: item.id for item in facts.functions}
    guarded = {item.enclosing_function_id for item in facts.sanitizers if item.kind == "authorization_guard"}

    assert functions["admin_panel"] in guarded
    assert functions["profile"] not in guarded


def test_fastapi_query_dependency_bridges_to_route_handler_flow(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import Depends, FastAPI, Query\n"
        "app = FastAPI()\n"
        "def read_search(q: str = Query('')):\n"
        "    normalized = q.strip()\n"
        "    return normalized\n"
        "@app.get('/search')\n"
        "def search(term: str = Depends(read_search)):\n"
        '    sql = "SELECT * FROM products WHERE name = \'" + term + "\'"\n'
        "    return cursor.execute(sql)\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    candidates = build_trace_candidates(facts, build_graph(facts))
    functions = {item.name: item.id for item in facts.functions}
    bridged = [item for item in facts.sources if item.enclosing_function_id == functions["search"] and item.variables == ["term"]]

    assert any(item.kind == "http_query" and "read_search" in item.expression for item in bridged)
    assert any(item.vuln_class == "injection" and item.source.symbol == "term" for item in candidates)


def test_fastapi_security_and_transitive_annotated_body_dependencies_bridge(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import Body, Depends, FastAPI, Header, Security\n"
        "app = FastAPI()\n"
        "def read_tenant(x_tenant: str = Header('')):\n"
        "    return x_tenant\n"
        "def read_payload(payload: Annotated[str, Body()]):\n"
        "    return payload\n"
        "def payload_wrapper(value: str = Depends(read_payload)):\n"
        "    return value\n"
        "@app.post('/items')\n"
        "def create_item(\n"
        "    tenant: str = Security(read_tenant),\n"
        "    body_value: str = Depends(payload_wrapper),\n"
        "):\n"
        "    return cursor.execute(tenant + body_value)\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    functions = {item.name: item.id for item in facts.functions}
    handler_sources = {
        (item.kind, tuple(item.variables)) for item in facts.sources if item.enclosing_function_id == functions["create_item"]
    }

    assert ("http_header", ("tenant",)) in handler_sources
    assert ("http_body", ("body_value",)) in handler_sources


def test_fastapi_plain_or_non_returned_dependencies_are_not_user_sources(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import Depends, FastAPI, Query\n"
        "app = FastAPI()\n"
        "def get_db():\n"
        "    return object()\n"
        "def ignores_query(q: str = Query('')):\n"
        "    audit_log(q)\n"
        "    return 'fixed'\n"
        "@app.get('/items')\n"
        "def items(db = Depends(get_db), fixed = Depends(ignores_query)):\n"
        "    return db.execute(fixed)\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    functions = {item.name: item.id for item in facts.functions}
    bridged_variables = {
        variable for item in facts.sources if item.enclosing_function_id == functions["items"] for variable in item.variables
    }

    assert "db" not in bridged_variables
    assert "fixed" not in bridged_variables


def test_drf_body_and_path_containers_are_sources(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def update(request, kwargs, db):\n"
        "    title = request.data['title']\n"
        "    item_id = kwargs['item_id']\n"
        "    return db.execute(title + item_id)\n",
        encoding="utf-8",
    )

    facts = scan_repo(tmp_path)
    kinds = {(item.kind, tuple(item.variables)) for item in facts.sources}

    assert ("http_body", ("title",)) in kinds
    assert ("http_path", ("item_id",)) in kinds
