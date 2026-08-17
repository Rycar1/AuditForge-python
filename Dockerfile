# syntax=docker/dockerfile:1
#
# The default image includes the optional Java, Go and TypeScript toolchains so
# a containerized scan retains the same AST-capable language coverage as a
# fully provisioned local installation. Pass
# --build-arg AUDITFORGE_WITH_TOOLCHAINS=0 for a smaller Python-only image.
FROM python:3.11-slim-bookworm

ARG AUDITFORGE_WITH_TOOLCHAINS=1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/auditforge \
    XDG_CACHE_HOME=/var/cache/auditforge \
    NODE_PATH=/usr/local/lib/node_modules

WORKDIR /opt/auditforge

RUN set -eux; \
    case "${AUDITFORGE_WITH_TOOLCHAINS}" in \
        1|true|TRUE|yes|YES) \
            apt-get update; \
            apt-get install --no-install-recommends --yes ca-certificates golang-go nodejs npm openjdk-17-jdk-headless; \
            npm install --global --no-audit --no-fund typescript@5; \
            npm cache clean --force; \
            rm -rf /var/lib/apt/lists/* ;; \
        0|false|FALSE|no|NO) \
            : ;; \
        *) \
            echo "AUDITFORGE_WITH_TOOLCHAINS must be 0 or 1" >&2; exit 2 ;; \
    esac; \
    groupadd --system --gid 10001 auditforge; \
    useradd --system --uid 10001 --gid auditforge --create-home --home-dir /home/auditforge --shell /usr/sbin/nologin auditforge; \
    mkdir -p /workspace /source /validation-queue /var/cache/auditforge; \
    chown -R auditforge:auditforge /home/auditforge /workspace /source /validation-queue /var/cache/auditforge

COPY pyproject.toml README.md ./
COPY auditforge ./auditforge

RUN python -m pip install --no-cache-dir .

USER auditforge

EXPOSE 8765

VOLUME ["/workspace", "/validation-queue", "/var/cache/auditforge"]

ENTRYPOINT ["auditforge"]
CMD ["serve", "--workspace", "/workspace", "--host", "0.0.0.0", "--port", "8765", "--allowed-repo-root", "/source"]
