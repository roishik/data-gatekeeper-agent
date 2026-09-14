# Cloud Run image for the data-gatekeeper-agent webhook service.
#
# Multi-stage: uv resolves and installs dependencies into a venv in the
# builder stage, and only that venv + the app code (no uv binary, no
# build cache) ships in the final image -- smaller image, smaller attack
# surface for a service that holds real credentials.

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /build
COPY pyproject.toml uv.lock ./
# --frozen: install exactly what uv.lock pins, never re-resolve inside
# the build -- reproducible images, and a build fails loudly instead of
# silently drifting if uv.lock and pyproject.toml disagree.
# --no-install-project: only dependencies go into the venv here; the app
# code is copied in directly below rather than pip-installed, which
# keeps a plain `uvicorn app.main:app` runnable with no build/install
# step of its own.
RUN uv venv /opt/venv && \
    UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project --no-dev

FROM python:3.12-slim

# Never run a credential-holding service as root.
RUN useradd --create-home --uid 10001 gatekeeper
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY app/ ./app/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    # Cloud Run injects PORT at runtime; 8080 matches its own default
    # and app/config.py's own fallback, so a local `docker run` without
    # -e PORT=... still works the same way.
    PORT=8080

USER gatekeeper

EXPOSE 8080

# Shell form so ${PORT} expands -- Cloud Run sets PORT per-revision and
# expects the container to actually listen on it, not on a value baked
# in at build time.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
