# Multi-stage: install into a staging prefix, copy into a minimal runtime image.
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
LABEL org.opencontainers.image.title="detection-platform operator-console"
LABEL org.opencontainers.image.description="Human control plane for AI-proposed Sigma detections"

RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /install /usr/local
WORKDIR /app
COPY app/ ./app/
RUN mkdir -p /data && chown appuser:appuser /data
USER appuser
EXPOSE 8000

# stdlib-only healthcheck (slim image has no curl)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--access-log"]
