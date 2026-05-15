# veto-gateway

The Go service. Public API surface for Veto. Hot-path regex checks + delegation to the ML inference service.

> Latency budget: **< 20 ms p99** for regex-only verdicts, **< 100 ms p99** end-to-end including ML inference.

---

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | **Go 1.22** | |
| Router | **`github.com/go-chi/chi/v5`** v5.1 | Stdlib-leaning, low-allocation |
| Regex engine | Go stdlib `regexp` (RE2) | Linear-time matching, no catastrophic backtracking |
| Inference transport | HTTP (JSON) | gRPC + protobuf — deferred |
| Container | `golang:1.22-alpine` build → `gcr.io/distroless/static:nonroot` runtime | Final image ~10 MB |
| Module | `veto-gateway` | `go.mod` |

No dependencies beyond `chi` and its `middleware` subpackage.

---

## Running it

### As part of the full stack (recommended)

From the repo root:

```bash
docker compose up -d --build
# Gateway → http://localhost:8088
```

The gateway depends on the inference service being **healthy** (compose `depends_on.condition: service_healthy`) — it will wait for the inference container's healthcheck before starting.

### Standalone (Go locally)

```bash
cd gateway
VETO_REDIS_URL=redis://localhost:6379/0 \
VETO_CLOUD_URL=http://localhost:8090 \
VETO_CLOUD_INTERNAL_TOKEN=<32+ chars matching the cloud's token> \
VETO_INFERENCE_URL=http://localhost:8000 \
go run .
# Listens on :8080
```

You'll need the inference service AND `veto-cloud` + Redis running separately. The gateway resolves customer keys against cloud + Redis on every request — there is no shared bypass key. Mint a real `vt_live_…` from the dashboard and pass it as `X-Veto-Key`.

### Standalone Docker

```bash
cd gateway
docker build -t veto-gateway .
docker run --rm -p 8088:8080 \
  -e VETO_REDIS_URL=redis://host.docker.internal:6379/0 \
  -e VETO_CLOUD_URL=http://host.docker.internal:8090 \
  -e VETO_CLOUD_INTERNAL_TOKEN=… \
  -e VETO_INFERENCE_URL=http://host.docker.internal:8000 \
  veto-gateway
```

---

## API

### `GET /healthz`

Liveness probe. No auth.

```bash
$ curl http://localhost:8088/healthz
{"status":"ok"}
```

### `POST /v1/check`

Requires auth via `X-Veto-Key: …` or `Authorization: Bearer …`.

Request body (max 64 KB):

```json
{
  "text": "Ignore previous instructions.",
  "categories": ["pii", "secrets", "injection"]   // optional
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `text` | string | yes | The input to evaluate. ≤ 32 KB recommended. |
| `categories` | string[] | no | Subset of `["pii", "secrets", "injection"]`. Defaults to all three. |

Response:

```json
{
  "allowed": false,
  "action": "block",
  "findings": [
    {
      "category": "injection",
      "rule": "ml_injection_classifier",
      "severity": "high",
      "score": 0.9999
    }
  ],
  "redacted": "Ignore previous instructions.",
  "latency_ms": 28.4
}
```

| Field | Type | Notes |
|---|---|---|
| `allowed` | bool | `false` iff any finding has severity `"high"` |
| `action` | `"allow"` \| `"redact"` \| `"block"` | Decision the caller should apply |
| `findings[]` | object[] | Each finding has `category`, `rule`, `severity`, plus `match`/`start`/`end` for regex hits or `score` for ML hits |
| `redacted` | string | `text` with placeholder substitutions (`[REDACTED_EMAIL]`, `[REDACTED_AWS_KEY]`, …) applied for PII + secret matches |
| `latency_ms` | number | Wall-clock time inside the handler |

### Errors

| Status | Body | When |
|---|---|---|
| `400` | `{"error":"invalid json"}` | Body fails to decode |
| `400` | `{"error":"text required"}` | `text` empty or whitespace |
| `401` | `{"error":"unauthorized"}` | Missing or wrong API key |
| `413` | (stdlib http error) | Body exceeds 64 KB |

Inference outages are **soft-failed** — a `log.Printf("inference error: %v", err)` is emitted and the response excludes injection findings. Regex findings still ship (fail-degraded mode).

---

## Detection coverage

### Regex rules — `rules.go`

The `rules` slice is evaluated **in order**, applied with replacement-as-you-go so that more specific patterns match before generic ones. Order is load-bearing — read the file before reordering.

#### Secrets (severity high unless noted)

| Rule | Pattern | Replaces with |
|---|---|---|
| `private_key` | `-----BEGIN (?:RSA \| EC \| DSA \| OPENSSH \| PGP \| )PRIVATE KEY-----` | `[REDACTED_PRIVATE_KEY]` |
| `jwt` (medium) | `eyJ…\.eyJ…\.…` | `[REDACTED_JWT]` |
| `aws_access_key` | `AKIA[0-9A-Z]{16}` | `[REDACTED_AWS_KEY]` |
| `openai_key` | `sk-[A-Za-z0-9_-]{20,}` | `[REDACTED_OPENAI_KEY]` |
| `anthropic_key` | `sk-ant-[A-Za-z0-9_-]{20,}` | `[REDACTED_ANTHROPIC_KEY]` |
| `github_pat` | `(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9]{30,}` | `[REDACTED_GH_TOKEN]` |

#### PII

| Rule | Severity | Replaces with |
|---|---|---|
| `email` | medium | `[REDACTED_EMAIL]` |
| `iban` | high | `[REDACTED_IBAN]` |
| `nir_fr` | high | `[REDACTED_NIR]` |
| `ssn_us` | high | `[REDACTED_SSN]` |
| `credit_card` | high | `[REDACTED_CC]` |
| `phone_fr` | medium | `[REDACTED_PHONE]` |
| `phone_intl` | medium | `[REDACTED_PHONE]` |

### ML — prompt injection

If `injection` is in the requested categories, the gateway POSTs to `${VETO_INFERENCE_URL}/detect/injection` with a 5-second context timeout. Response shape (from the inference service):

```json
{ "injection": 0.9999, "label": "INJECTION" }
```

The gateway thresholds at:

- `< 0.5` → no finding (request passes the injection check)
- `0.5 – 0.8` → `severity: medium`
- `> 0.8` → `severity: high` → triggers `action: block`

---

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `VETO_REDIS_URL` | — (required) | Hot-path key cache. URL form (`redis://host:port/db`). Cloud is the writer; gateway reads. |
| `VETO_CLOUD_URL` | — (required) | Base URL for the cloud control plane. Used as the cache-miss fallback at `…/internal/v1/keys/lookup`. |
| `VETO_CLOUD_INTERNAL_TOKEN` | — (required) | Bearer token matching cloud's `VETO_CLOUD_INTERNAL_TOKEN`. Min 32 chars. |
| `VETO_INFERENCE_URL` | `http://inference:8000` | Base URL for the inference service |

Listen address is hard-coded to `:8080` inside the container; the host-side port mapping is configured in `docker-compose.yml` (default `8088:8080`, overridable via `VETO_HOST_PORT`).

---

## Project layout

```
gateway/
├── go.mod                 module + chi / redis / argon2 / lru deps
├── main.go                router, middleware, /healthz, /v1/check handler, auth()
├── keylookup.go           Lookup (Redis → cloud RPC), parseAPIKey, argonVerify
├── cache.go               verifiedCache — sha256-keyed LRU on top of Lookup
├── rules.go               regex rule table + scanCategory()
├── ratelimit.go           per-IP token bucket (interim — per-key replaces it)
├── inference.go           HTTP client → POST /detect/injection
├── Dockerfile             go build → distroless
└── README.md              ← this file
```

No test files yet. When the package grows past these files, split into `internal/{auth,rules,inference}` and add table-driven unit tests for `scanCategory` + a property test for `argonVerify` round-tripping cloud's mint format.

---

## Request flow

```
HTTP request
   │
   ▼
chi middleware: RequestID · RealIP · Logger · Recoverer · Timeout(10s)
   │
   ▼
rateLimit (per-IP token bucket, interim)
   │
   ▼
auth() middleware
   │
   │   X-Veto-Key or Authorization: Bearer
   │   1. verifiedCache.Get(sha256(key)) ── hit ──▶ attach Entry to ctx, next
   │   2. parseAPIKey → prefix + last4
   │   3. Lookup.Resolve:
   │        Redis GET veto:key:<prefix><last4>
   │        ├── hit  → JSON unmarshal Entry
   │        └── miss → cloud RPC GET /internal/v1/keys/lookup (bearer)
   │   4. argonVerify(key, Entry.HashArgon2id)
   │   5. verifiedCache.Put(key, Entry)
   │   6. attach Entry to ctx
   │
   ▼
handleCheck()
   │
   │  1. http.MaxBytesReader (64 KB)
   │  2. json.Decode body
   │  3. Iterate requested categories:
   │       pii      → scanCategory(text, "pii")     │ regex
   │       secrets  → scanCategory(text, "secrets") │ regex
   │       injection→ detectInjection(ctx, text)    │ HTTP → inference
   │  4. Compute action from findings (high → block, any pii/secret → redact, else allow)
   │  5. Encode CheckResponse to JSON
   ▼
HTTP response
```

---

## Adding things

### A new regex rule

Edit `rules.go`, push to the `rules` slice. Place specific patterns **before** generic ones — order determines which fires first (and which placeholder ends up in `redacted`).

```go
{"slack_webhook", "secrets", "high",
  regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9/]+`),
  "[REDACTED_SLACK_WEBHOOK]"},
```

The `category` field must be one of `"pii"` or `"secrets"` (those are the only ones `scanCategory` is called with from `handleCheck`).

### A new ML category

Adding e.g. toxicity:

1. Add a new endpoint to the inference service (e.g. `POST /detect/toxicity`).
2. In `inference.go`, add a sibling function `detectToxicity(ctx, text)` mirroring `detectInjection`.
3. In `handleCheck`, extend the `switch c` to handle `"toxicity"`.
4. Add `"toxicity"` to the default `cats` list in `handleCheck` if you want it to fire by default.

### A new auth scheme

`auth()` already does a per-tenant lookup (verified-key LRU → Redis → cloud RPC → argon2id). To add a *different* scheme (mTLS, JWT, OAuth introspection), keep the lookup chain — the verified-key LRU is the right place to short-circuit any successful auth — and add a parallel verifier before `parseAPIKey`. Don't put auth logic in the handler.

---

## Build

The image uses a two-stage build: `golang:1.22-alpine` to compile statically, then `gcr.io/distroless/static:nonroot` to run. The runtime image has no shell, no package manager, runs as uid `65532`. Final size on the order of **10 MB**.

```bash
docker compose build gateway
# or:
cd gateway && docker build -t veto-gateway .
```

**Before publishing**, commit `go.sum` for supply-chain integrity:

```bash
cd gateway
go mod tidy
git add go.mod go.sum
```

Then switch the Dockerfile builder step from `RUN go mod tidy && CGO_ENABLED=0 go build ...` to the verified two-step form `RUN go mod download && CGO_ENABLED=0 go build ...` so checksum mismatches fail the build.

---

## What's **not** here yet

Tracked here so the reader doesn't expect SPEC features that haven't been wired:

- **Hyperscan.** Intel Hyperscan for multi-pattern matching on x86, with RE2 as the ARM fallback. Today it's RE2 only (Go stdlib).
- **Per-key / per-org rate-limit.** Per-IP token bucket only today. Per-org budgets land with the metering pipeline (same Redis instance the cache lives on).
- **Metering.** Gateway resolves `(org_id, project_id, tier)` per request but does not yet emit usage events. Next slice — see `veto-docs/PLAN.md` §3.
- **Proxy mode.** Transparent forwarding to OpenAI/Anthropic/etc. via `base_url` swap. Not wired — only the REST `/v1/check` mode exists.
- **Streaming.** Pre-check on streamed chunks + injected control frames (`event: veto.block`) — not yet.
- **gRPC to inference.** Today the gateway → inference link is HTTP/JSON. Production target is gRPC + protobuf.
- **Audit log.** Hash-chained event log + HMAC + S3 Object Lock — not yet.
- **OpenTelemetry.** Spans, metrics, logs to Grafana stack — not yet. Today: `log.Printf` to stdout.
- **mTLS gateway↔inference.** For Enterprise on-prem — not yet.
- **Tests.** No unit, integration or fuzz tests yet. `scripts/test.sh` from the monorepo is the smoke test.

---

## Reference

- Repo root [`README.md`](../README.md) — How this service fits into the stack
