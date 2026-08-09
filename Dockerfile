ARG BASE_IMAGE=python:3.13-slim
FROM ${BASE_IMAGE}

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
    && mkdir -p /var/lib/malapp /workspace /opt/malapp-seed \
    && chown -R malapp:malapp /var/lib/malapp /workspace /opt/malapp-seed

COPY --chown=malapp:malapp engine /app/engine
COPY --chown=malapp:malapp web /app/web
COPY --chown=malapp:malapp hermes /app/hermes
COPY --chown=malapp:malapp run.py /app/run.py
COPY --chown=malapp:malapp docker/entrypoint.sh /usr/local/bin/malapp-entrypoint

COPY --chown=malapp:malapp data/schema.json /opt/malapp-seed/schema.json
COPY --chown=malapp:malapp data/field_mapping.json /opt/malapp-seed/field_mapping.json
COPY --chown=malapp:malapp data/sample_conflict.json /opt/malapp-seed/sample_conflict.json
COPY --chown=malapp:malapp data/eval/best_params.json /opt/malapp-seed/eval/best_params.json

RUN sed -i 's/\r$//' /usr/local/bin/malapp-entrypoint \
    && chmod 0555 /usr/local/bin/malapp-entrypoint

USER 10001:10001

EXPOSE 8765
VOLUME ["/var/lib/malapp", "/workspace"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=4 \
  CMD python -c "import json,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3); d=json.load(r); raise SystemExit(0 if d.get('status') == 'ok' else 1)"

ENTRYPOINT ["/usr/local/bin/malapp-entrypoint"]
CMD ["python", "-u", "run.py"]
