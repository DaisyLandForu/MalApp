ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ARG MALAPP_EXTRAS=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    MALAPP_HOST=0.0.0.0 \
    MALAPP_PORT=8765 \
    MALAPP_DATA_DIR=/var/lib/malapp \
    MALAPP_WORKSPACE_ROOT=/workspace \
    MALAPP_USE_LOCAL_QWEN=0

WORKDIR /app

RUN groupadd --gid 10001 malapp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin malapp \
    && mkdir -p /var/lib/malapp /workspace \
    && chown -R malapp:malapp /var/lib/malapp /workspace

COPY pyproject.toml README.md /app/
COPY apps /app/apps
COPY integrations /app/integrations
COPY malapp /app/malapp
COPY scripts /app/scripts
COPY training /app/training
COPY deploy/docker/entrypoint.sh /usr/local/bin/malapp-entrypoint

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".${MALAPP_EXTRAS}" \
    && sed -i 's/\r$//' /usr/local/bin/malapp-entrypoint \
    && chmod 0555 /usr/local/bin/malapp-entrypoint \
    && chown -R malapp:malapp /app

USER 10001:10001

EXPOSE 8765
VOLUME ["/var/lib/malapp", "/workspace"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=4 \
  CMD python -c "import json,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3); d=json.load(r); raise SystemExit(0 if d.get('status') == 'ok' else 1)"

ENTRYPOINT ["/usr/local/bin/malapp-entrypoint"]
CMD ["python", "-m", "apps.server.main"]
