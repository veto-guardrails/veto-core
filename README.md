# veto-core

**Veto** is a runtime guardrail layer for LLM applications. It sits between your app and the model, blocking PII leaks, prompt injection, secrets, and toxicity in milliseconds.

`veto-core` is the open-source heart of the project: the gateway, the regex engine, the ONNX runner, and OSS model wrappers. Apache-2.0.

---

## What's in here

```
veto-core/
├── gateway/             Go service — public /v1/check API, regex hot path     → gateway/README.md
├── inference/           Python service — ML classifiers (uv-managed)          → inference/README.md
├── scripts/
│   └── test.sh          curl smoke-test against a live gateway
├── docker-compose.yml   brings up gateway + inference together
├── LICENSE              Apache-2.0
└── README.md            ← this file
```

Each subdirectory has its own README with deeper details — read those after this one.

---

## Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │           Customer app / browser              │
                  └─────────────┬─────────────────────────────────┘
                                │  REST · SDK · proxy
                                ▼
                ┌───────────────────────┐
                │  veto-gateway (Go)    │
                │  :8088                │
                │  POST /v1/check       │
                │  · auth (X-Veto-Key)  │
                │  · regex: PII + secrets│
                │  · forwards to ML     │
                └─────────────┬─────────┘
                              │ HTTP (gRPC target)
                              ▼
                ┌─────────────────────────────┐
                │  veto-inference (Python)    │
                │  :8000 (internal-only)      │
                │  POST /detect/injection     │
                │  · prompt-injection ML clf  │
                └─────────────────────────────┘
```

The gateway is the **only externally reachable service**. The inference container is on the compose network only — never published.

---

## Run the stack

Requires Docker + Docker Compose v2.

```bash
docker compose up -d --build
# gateway  → http://localhost:8088
# inference→ internal only
```

First build downloads the prompt-injection model (~750 MB) and the torch CPU wheels into the inference image. Subsequent builds use the cache and finish in seconds.

To stop:

```bash
docker compose down
```

### Port collisions

If `:8088` is busy on the host:

```bash
VETO_HOST_PORT=18088 docker compose up -d --build
```

---

## Smoke test

```bash
# VETO_API_KEY is required — there's no dev-sentinel fallback. Mint a real
# vt_live_… key from the dashboard first.
VETO_API_KEY=vt_live_… bash scripts/test.sh
# or against a non-default URL:
VETO_URL=http://localhost:18088 VETO_API_KEY=vt_live_… bash scripts/test.sh
```

A 9-call matrix against `POST /v1/check`:

| Sample | Expected `action` |
|---|---|
| Clean prompt | `allow` |
| Email PII | `redact` |
| AWS access-key leak | `block` (severity high) |
| OpenAI API-key leak | `block` |
| French IBAN | `block` (severity high) |
| Prompt injection ("Ignore all previous instructions…") | `block` (via ML classifier) |
| Multi-finding (email + IBAN + injection) | `block` |
| `categories: ["pii"]` override on a payload with a secret | `redact` only |

Pipe through `| jq .` to pretty-print, or comment that out at the top of `scripts/test.sh` if you don't have jq.

---

## Environment

| Variable | Default | Service | Purpose |
|---|---|---|---|
| `VETO_REDIS_URL` | — (required) | gateway | Hot-path key cache (cloud writes, gateway reads) |
| `VETO_CLOUD_URL` | — (required) | gateway | Control-plane base URL for the cache-miss key lookup |
| `VETO_CLOUD_INTERNAL_TOKEN` | — (required) | gateway | Bearer for the internal cloud RPC (matches `veto-cloud`'s token) |
| `VETO_HOST_PORT` | `8088` | compose | Host-side port for gateway |
| `VETO_INFERENCE_URL` | `http://inference:8000` | gateway | Base URL for ML classifier |
| `VETO_INJECTION_MODEL` | `protectai/deberta-v3-base-prompt-injection-v2` | inference | HuggingFace model id |
| `VETO_MAX_LEN` | `512` | inference | Tokenizer max length |
| `HF_HOME` | `/models` | inference | HuggingFace cache (baked into image at build) |

The API key (a real `vt_live_…` minted from the dashboard) is sent by the caller as `X-Veto-Key` and never logged.

---

## What's **not** here yet

This repo is the prototype shape. Items on the roadmap that haven't landed:

- **Hyperscan** multi-pattern regex (RE2 stdlib only today).
- **Redis-backed per-org rate-limit + metering.** Customer-key auth is wired (Redis + cloud RPC + argon2id, in-process LRU on top); rate-limit is still per-IP only and metering events aren't emitted yet.
- **Streaming guardrails** — `/v1/check` is request/response only.
- **Proxy mode** — `base_url`-swap for OpenAI/Anthropic/etc. transparent forwarding.
- **gRPC** gateway↔inference (HTTP/JSON today).
- **ONNX Runtime + INT8.** Eager-mode PyTorch only today.
- **GLiNER + Presidio NER** for richer PII coverage.
- **Toxicity classifier.**
- **`veto-injector-v2`** (distilled own model).
- **Helm chart skeleton** for on-prem.
- **Python + TypeScript SDKs.**
- **OpenTelemetry.** stdout logging only today.

The premium **Veto Fused** model and the multi-tenant control plane (billing, audit chain, dashboard) live in private repos and are not part of `veto-core`.

---

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
