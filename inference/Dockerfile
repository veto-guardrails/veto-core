FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_NO_SYNC=1 \
    PATH="/app/.venv/bin:$PATH" \
    HF_HOME=/models \
    TRANSFORMERS_NO_ADVISORY_WARNINGS=1 \
    TOKENIZERS_PARALLELISM=false

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

ARG INJECTION_MODEL=protectai/deberta-v3-base-prompt-injection-v2
ENV VETO_INJECTION_MODEL=${INJECTION_MODEL}
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('${INJECTION_MODEL}'); \
    AutoModelForSequenceClassification.from_pretrained('${INJECTION_MODEL}')"

COPY app.py .

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=10 \
  CMD curl -fsS http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
