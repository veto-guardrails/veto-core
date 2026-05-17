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

### Standalone (OSS, no control plane)

Set `VETO_STATIC_KEYS` to a comma-separated list of `<plaintext>:<org_id>:<tier>` triples and the gateway resolves keys from the env var — no Redis, no `veto-cloud`, no dependencies beyond `inference`.

```bash
# Generate a random plaintext key once (32 bytes base32, no padding, vt_live_ prefix):
KEY=$(printf 'vt_live_'; head -c 32 /dev/urandom | base32 | tr -d '=' | tr '[:upper:]' '[:lower:]')
echo "$KEY"   # save this — it's your gateway credential

VETO_STATIC_KEYS="$KEY:my-org:free" docker compose up -d --build
# gateway  → http://localhost:8088
# inference→ internal only

curl -X POST http://localhost:8088/v1/check \
  -H "X-Veto-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"my email is leak@example.com"}'
```

Static mode disables metering + per-org rate-limit (they need Redis). Per-IP rate-limit + key auth still apply. Suitable for self-hosting, evaluation, and CI smoke tests.

To "revoke" a key, restart the gateway with an updated `VETO_STATIC_KEYS`.

### Managed (with `veto-cloud` control plane)

For multi-tenant, billing, dashboard, and revocable keys, run the gateway alongside the proprietary `veto-cloud` service:

```bash
docker compose up -d --build
# gateway  → http://localhost:8088
# inference→ internal only
```

Requires `VETO_CLOUD_URL`, `VETO_CLOUD_INTERNAL_TOKEN`, and `VETO_REDIS_URL` set. The cloud service implements the `/internal/v1/keys/lookup` RPC and writes the cache entries Redis serves. See `veto-cloud` (private) or implement the contract yourself — `config/keycache.go` documents the wire format.

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
| `VETO_STATIC_KEYS` | — | gateway | Standalone mode — `key:org:tier` triples (comma-separated). When set, gateway skips Redis + cloud lookup. |
| `VETO_REDIS_URL` | — (required in managed mode) | gateway | Hot-path key cache + metering stream + per-org rate-limit. Optional in static mode. |
| `VETO_CLOUD_URL` | — (required in managed mode) | gateway | Control-plane base URL for the cache-miss key lookup. Unused in static mode. |
| `VETO_CLOUD_INTERNAL_TOKEN` | — (required in managed mode) | gateway | Bearer for the internal cloud RPC. Unused in static mode. |
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
