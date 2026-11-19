from __future__ import annotations

from pathlib import Path

from auditforge.candidates import build_trace_candidates
from auditforge.graph import build_graph
from auditforge.scanner import scan_repo
from auditforge.semantic_findings import generate_semantic_candidates


def test_semantic_findings_detect_source_less_security_issues_without_secret_disclosure(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "SECRET_KEY = 'production-secret-value'\n"
        "def password_hash(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n"
        "app.run(debug=True)\n",
        encoding="utf-8",
    )

    candidates = generate_semantic_candidates(tmp_path, scan_repo(tmp_path), [])

    assert {item.taxonomy_id for item in candidates} == {
        "hardcoded_secret",
        "insecure_configuration",
        "weak_cryptography",
    }
    serialized = str([item.to_dict() for item in candidates])
    assert "production-secret-value" not in serialized


def test_semantic_findings_ignore_placeholder_secret_and_checksum_hash(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "import hashlib\nSECRET_KEY = 'changeme'\ndef checksum(data):\n    return hashlib.md5(data).hexdigest()\n",
        encoding="utf-8",
    )

    candidates = generate_semantic_candidates(tmp_path, scan_repo(tmp_path), [])

    assert candidates == []


def test_semantic_findings_detect_object_level_authorization_gap(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.get('/profile')\n"
        "def profile(db):\n"
        "    user_id = request.args.get('user_id')\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    existing = build_trace_candidates(facts, build_graph(facts))

    candidates = generate_semantic_candidates(tmp_path, facts, existing)

    authz = next(item for item in candidates if item.taxonomy_id == "authorization_failure")
    assert authz.cwe_ids == ["CWE-639", "CWE-862"]
    assert authz.route_id


def test_vague_same_scope_guard_clues_do_not_hide_object_authorization_gap(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.get('/profile/{user_id}')\n"
        "def profile(user_id, actor, db, tenant_context=True):\n"
        "    checked = haspermission(actor)\n"
        "    if tenant_context:\n"
        "        audit(checked)\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    existing = build_trace_candidates(facts, build_graph(facts))

    candidates = generate_semantic_candidates(tmp_path, facts, existing)

    assert any(item.taxonomy_id == "authorization_failure" for item in candidates)


def test_explicit_framework_permission_policy_can_suppress_object_gap_heuristic(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def require_admin():\n"
        "    return True\n"
        "@app.get('/profile/{user_id}')\n"
        "def profile(user_id: str, actor=Depends(require_admin), db=None):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    existing = build_trace_candidates(facts, build_graph(facts))

    candidates = generate_semantic_candidates(tmp_path, facts, existing)

    assert not any(item.taxonomy_id == "authorization_failure" for item in candidates)


def test_resource_lookup_by_request_id_is_detected_without_sql_injection(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.get('/accounts')\n"
        "def account():\n"
        "    account_id = request.args.get('account_id')\n"
        "    return Account.objects.get(pk=account_id)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)

    candidates = generate_semantic_candidates(tmp_path, facts, [])

    authz = next(item for item in candidates if item.taxonomy_id == "authorization_failure")
    assert authz.sink.start_line == 5
    assert "account.objects.get" in authz.static_evidence


def test_resource_lookup_scoped_by_tenant_is_not_reported_as_idor(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.get('/accounts')\n"
        "def account(current_tenant):\n"
        "    account_id = request.args.get('account_id')\n"
        "    return Account.objects.get(pk=account_id, tenant=current_tenant)\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)

    candidates = generate_semantic_candidates(tmp_path, facts, [])

    assert not any(item.taxonomy_id == "authorization_failure" for item in candidates)


def test_configuration_and_iac_security_models_are_reported_without_secret_disclosure(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  api:\n    privileged: true\n", encoding="utf-8")
    (tmp_path / "application.properties").write_text("management.endpoints.web.exposure.include=health,gateway\n", encoding="utf-8")
    (tmp_path / ".env").write_text("DATABASE_PASSWORD=real-production-password\n", encoding="utf-8")

    candidates = generate_semantic_candidates(tmp_path, scan_repo(tmp_path), [])

    assert {item.taxonomy_id for item in candidates} >= {"insecure_configuration", "hardcoded_secret"}
    assert "real-production-password" not in str([item.to_dict() for item in candidates])


def test_github_actions_security_models_detect_pinned_actions_and_pr_target_execution(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "insecure.yml").write_text(
        "name: insecure-ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  audit:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: vendor/example-action@v2\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: ./audit-pr-code.sh\n",
        encoding="utf-8",
    )

    candidates = generate_semantic_candidates(tmp_path, scan_repo(tmp_path), [])

    findings = {item.source.symbol: item for item in candidates if item.source.file == ".github/workflows/insecure.yml"}
    assert "GitHub Action vendor/example-action" in findings
    assert "GitHub Actions write-all permission" in findings
    pr_target = findings["pull_request_target checks out pull request code"]
    assert pr_target.confidence == "high"
    assert pr_target.cwe_ids == ["CWE-94", "CWE-829"]


def test_github_actions_pinned_or_unprivileged_workflow_is_not_reported(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "safe.yml").write_text(
        "name: safe-ci\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: vendor/example-action@0123456789abcdef0123456789abcdef01234567\n"
        "      - run: pytest -q\n",
        encoding="utf-8",
    )

    candidates = generate_semantic_candidates(tmp_path, scan_repo(tmp_path), [])

    assert not any(item.source.file == ".github/workflows/safe.yml" for item in candidates)


def test_php_dynamic_include_connects_global_path_source_and_respects_allowlist(tmp_path: Path) -> None:
    source_dir = tmp_path / "vulnerabilities" / "fi" / "source"
    source_dir.mkdir(parents=True)
    (source_dir / "low.php").write_text("<?php\n$file = $_GET['page'];\n", encoding="utf-8")
    (source_dir / "medium.php").write_text(
        "<?php\n$file = $_GET['page'];\n$file = str_replace(['http://', 'https://'], '', $file);\n",
        encoding="utf-8",
    )
    (source_dir / "high.php").write_text(
        "<?php\n$file = $_GET['page'];\nif (!fnmatch('file*', $file) && $file != 'include.php') { exit; }\n",
        encoding="utf-8",
    )
    (source_dir / "impossible.php").write_text(
        "<?php\n"
        "$file = $_GET['page'];\n"
        "$allowed = ['one.php', 'two.php'];\n"
        "if (!in_array($file, $allowed)) { exit; }\n",
        encoding="utf-8",
    )
    (tmp_path / "index.php").write_text(
        "<?php\n"
        "$variant = 'low.php';\n"
        "require \"vulnerabilities/fi/source/{$variant}\";\n"
        "include($file);\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    existing = build_trace_candidates(facts, build_graph(facts))

    candidates = generate_semantic_candidates(tmp_path, facts, existing)
    include_paths = [item for item in candidates if item.taxonomy_id == "path_traversal"]

    candidate = next(item for item in include_paths if item.source.file.endswith("low.php"))
    assert (candidate.source.start_line, candidate.sink.file, candidate.sink.start_line) == (2, "index.php", 4)
    assert not any(item.source.file.endswith("impossible.php") for item in include_paths)
    include_ssrf = [item for item in candidates if item.taxonomy_id == "server_side_request_forgery"]
    assert {Path(item.source.file).name for item in include_ssrf} == {"low.php", "medium.php"}


def test_php_persistent_xss_links_unencoded_write_to_proven_database_output(tmp_path: Path) -> None:
    (tmp_path / "write.php").write_text(
        "<?php\n"
        "$message = $_POST['message'];\n"
        "$message = mysqli_real_escape_string($db, $message);\n"
        "$query = \"INSERT INTO guestbook(message) VALUES ('$message')\";\n"
        "mysqli_query($db, $query);\n",
        encoding="utf-8",
    )
    (tmp_path / "safe-write.php").write_text(
        "<?php\n"
        "$message = $_POST['message'];\n"
        "$message = mysqli_real_escape_string($db, $message);\n"
        "$message = htmlspecialchars($message);\n"
        "$query = \"INSERT INTO guestbook(message) VALUES ('$message')\";\n"
        "mysqli_query($db, $query);\n",
        encoding="utf-8",
    )
    (tmp_path / "read.php").write_text(
        "<?php\n"
        "function render_guestbook($db) {\n"
        "    $query = 'SELECT message FROM guestbook';\n"
        "    $result = mysqli_query($db, $query);\n"
        "    $row = mysqli_fetch_row($result);\n"
        "    $message = $row[0];\n"
        "    $html .= \"<div>{$message}</div>\";\n"
        "}\n",
        encoding="utf-8",
    )
    facts = scan_repo(tmp_path)
    existing = build_trace_candidates(facts, build_graph(facts))

    candidates = generate_semantic_candidates(tmp_path, facts, existing)
    persistent = [
        item
        for item in candidates
        if item.taxonomy_id == "cross_site_scripting" and item.sink.file == "read.php" and item.sink.start_line == 7
    ]

    assert any(item.source.file == "write.php" and item.source.start_line == 2 for item in persistent)
    assert not any(item.source.file == "safe-write.php" for item in persistent)
