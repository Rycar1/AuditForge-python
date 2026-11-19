from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_docker_image_runs_the_dashboard_as_an_unprivileged_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.11-slim-bookworm" in dockerfile
    assert "AUDITFORGE_WITH_TOOLCHAINS" in dockerfile
    assert "openjdk-17-jdk-headless" in dockerfile
    assert "golang-go" in dockerfile
    assert "typescript@5" in dockerfile
    assert "USER auditforge" in dockerfile
    assert 'VOLUME ["/workspace", "/validation-queue", "/var/cache/auditforge"]' in dockerfile
    assert 'ENTRYPOINT ["auditforge"]' in dockerfile
    assert '"--allowed-repo-root", "/source"' in dockerfile


def test_compose_keeps_source_read_only_and_requires_remote_bind_security() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert "127.0.0.1:${AUDITFORGE_PORT:-8765}:8765" in compose
    assert 'AUDITFORGE_ALLOW_REMOTE: "1"' in compose
    assert "AUDITFORGE_ADMIN_TOKEN: ${AUDITFORGE_ADMIN_TOKEN:?" in compose
    assert "AUDITFORGE_ALLOWED_HOSTS:" in compose
    assert "AUDITFORGE_ALLOWED_ORIGINS:" in compose
    assert "${AUDITFORGE_SOURCE_DIR:-./source}:/source:ro" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "auditforge-workspace:/workspace" in compose
    assert "auditforge-cache:/var/cache/auditforge" in compose


def test_dockerignore_excludes_local_state_and_secrets_from_the_build_context() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert ".git/" in dockerignore
    assert "node_modules/" in dockerignore
    assert "workspace/" in dockerignore
    assert ".env" in dockerignore
    assert ".auditforge_*" in dockerignore


def test_deep_compose_uses_a_narrow_queue_only_runner_boundary() -> None:
    compose = (ROOT / "compose.deep.yaml").read_text(encoding="utf-8")

    assert "validation-runner:" in compose
    assert "AUDITFORGE_VALIDATION_RUNNER_MODE: queue" in compose
    assert "AUDITFORGE_VALIDATION_QUEUE: /validation-queue" in compose
    assert "auditforge-validation-queue:/validation-queue" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "host.docker.internal:host-gateway" in compose
    assert "/var/run/docker.sock" not in compose
    assert ":/source" not in compose
    assert ":/workspace" not in compose
