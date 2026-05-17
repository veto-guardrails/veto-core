package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type CheckRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories,omitempty"`
}

type Finding struct {
	Category string  `json:"category"`
	Rule     string  `json:"rule"`
	Severity string  `json:"severity"`
	Match    string  `json:"match,omitempty"`
	Start    int     `json:"start,omitempty"`
	End      int     `json:"end,omitempty"`
	Score    float64 `json:"score,omitempty"`
}

type CheckResponse struct {
	Allowed   bool      `json:"allowed"`
	Action    string    `json:"action"`
	Findings  []Finding `json:"findings"`
	Redacted  string    `json:"redacted,omitempty"`
	LatencyMs float64   `json:"latency_ms"`
}

const maxBodyBytes = 64 * 1024

var inferenceURL string

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	inferenceURL = envDefault("VETO_INFERENCE_URL", "http://inference:8000")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Static-key mode: when VETO_STATIC_KEYS is set, the gateway resolves
	// keys from the env var and skips the cloud RPC entirely. Lets the OSS
	// gateway run standalone without veto-cloud. Redis + metering stay
	// optional in this mode — they're only wired if VETO_REDIS_URL is set.
	staticKeys, err := parseStaticKeys(os.Getenv("VETO_STATIC_KEYS"))
	if err != nil {
		slog.Error("parse VETO_STATIC_KEYS", "err", err)
		os.Exit(1)
	}
	staticMode := len(staticKeys) > 0
	if staticMode {
		slog.Info("static-key mode", "keys", len(staticKeys))
	}

	var lookup *Lookup
	if !staticMode {
		lookup, err = newLookup(
			os.Getenv("VETO_REDIS_URL"),
			os.Getenv("VETO_CLOUD_URL"),
			os.Getenv("VETO_CLOUD_INTERNAL_TOKEN"),
		)
		if err != nil {
			slog.Error("key lookup init", "err", err)
			os.Exit(1)
		}
		defer lookup.Close()
	}
	verified := newVerifiedCache()

	redisURL := os.Getenv("VETO_REDIS_URL")
	var metering *Metering
	var orgRL *OrgRateLimiter
	if redisURL != "" {
		metering, err = newMetering(redisURL, envDefault("VETO_REGION", "single"))
		if err != nil {
			slog.Error("metering init", "err", err)
			os.Exit(1)
		}
		defer metering.Close()
		go metering.Run(ctx)

		orgRL, err = newOrgRateLimiter(redisURL)
		if err != nil {
			slog.Error("org rate limiter init", "err", err)
			os.Exit(1)
		}
		defer orgRL.Close()
	} else if !staticMode {
		// Dynamic mode without Redis would silently disable metering AND
		// can't even cache key lookups — fail loud at boot rather than
		// surprise operators in prod.
		slog.Error("VETO_REDIS_URL required in dynamic mode (omit it only when VETO_STATIC_KEYS is set)")
		os.Exit(1)
	} else {
		slog.Info("running without Redis (static-key mode) — metering + rate-limit disabled")
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(10 * time.Second))

	rps := envFloat("VETO_RATE_RPS", 1.0)   // 60 req/min steady-state
	burst := envFloat("VETO_RATE_BURST", 20) // short spike tolerance
	limiter := newIPLimiter(ctx, rps, burst)

	r.Get("/healthz", healthz)
	// Middleware order matters:
	//   rateLimit (per-IP)  → cheap, sheds obvious abuse before auth
	//   auth                → resolves Entry into ctx (org_id, tier, period)
	//   orgRateLimit        → per-org cap check, needs Entry
	//   handleCheck         → actual work + metering emit
	r.Post("/v1/check", rateLimit(limiter)(auth(lookup, verified, staticKeys, orgRateLimit(orgRL, handleCheck(metering)))))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", srv.Addr, "inference", inferenceURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "err", err)
	}
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envFloat(k string, d float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		slog.Warn("invalid env, using default", "key", k, "got", v, "default", d)
		return d
	}
	return f
}

type ctxKey int

const ctxKeyEntry ctxKey = 1

func entryFromCtx(ctx context.Context) (Entry, bool) {
	e, ok := ctx.Value(ctxKeyEntry).(Entry)
	return e, ok
}

// auth validates the presented customer key end-to-end. Two modes:
//
//  1. Static mode (VETO_STATIC_KEYS set): the env-var map is the source
//     of truth. A presented key is either in the map (allowed) or not
//     (unauthorized) — no Redis, no cloud, no argon2id.
//  2. Dynamic mode (default): parse → resolve (Redis → cloud RPC) →
//     argon2id verify. A verified-key LRU sits in front: a hit (within
//     TTL) skips both the lookup chain and argon2id, so a hot key
//     amortizes the ~50 ms hash to one verify per minute. Cache lookup
//     is keyed by sha256(plaintext) — last4 collisions can't promote
//     one customer's request into another's session.
//
// On success the resolved Entry is attached to the request context so
// downstream handlers (metering, per-org rate-limit) can read
// org/project/tier without re-querying.
func auth(lookup *Lookup, verified *verifiedCache, staticKeys map[string]Entry, next http.HandlerFunc) http.HandlerFunc {
	staticMode := len(staticKeys) > 0
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Veto-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		if staticMode {
			entry, ok := staticKeys[key]
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			next(w, r.WithContext(context.WithValue(r.Context(), ctxKeyEntry, entry)))
			return
		}

		if entry, ok := verified.Get(key); ok {
			next(w, r.WithContext(context.WithValue(r.Context(), ctxKeyEntry, entry)))
			return
		}
		prefix, last4, ok := parseAPIKey(key)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		lookupCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		entry, err := lookup.Resolve(lookupCtx, prefix, last4)
		if errors.Is(err, ErrKeyNotFound) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if err != nil {
			slog.WarnContext(r.Context(), "key lookup", "err", err, "prefix", prefix, "last4", last4)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "auth backend unavailable"})
			return
		}

		match, vErr := argonVerify(key, entry.HashArgon2id)
		if vErr != nil {
			slog.ErrorContext(r.Context(), "argon verify", "err", vErr, "key_id", entry.KeyID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth check failed"})
			return
		}
		if !match {
			// last4 collision is the only way to land here for a well-formed
			// key; the verify catches it. Log so we can spot abuse patterns.
			slog.InfoContext(r.Context(), "key argon mismatch", "prefix", prefix, "last4", last4)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		verified.Put(key, entry)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKeyEntry, entry)))
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleCheck(metering *Metering) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		// Read the body whole so we can attribute byte_count_in to the
		// metering event. Bodies are capped at 64 KiB above; the alloc is
		// bounded.
		raw, rerr := io.ReadAll(r.Body)
		if rerr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
			return
		}
		bytesIn := len(raw)

		var req CheckRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Text) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text required"})
			return
		}

		cats := req.Categories
		if len(cats) == 0 {
			cats = []string{"pii", "secrets", "injection"}
		}

		findings := []Finding{}
		redacted := req.Text
		var inferenceDur time.Duration

		for _, c := range cats {
			switch c {
			case "pii":
				f, red := scanCategory(redacted, "pii")
				findings = append(findings, f...)
				redacted = red
			case "secrets":
				f, red := scanCategory(redacted, "secrets")
				findings = append(findings, f...)
				redacted = red
			case "injection":
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				f, dur, err := detectInjection(ctx, req.Text)
				cancel()
				inferenceDur += dur
				if err != nil {
					slog.WarnContext(r.Context(), "inference", "err", err)
				} else {
					findings = append(findings, f...)
				}
			}
		}

		action := "allow"
		allowed := true
		for _, f := range findings {
			if f.Severity == "high" {
				action = "block"
				allowed = false
				break
			}
			if (f.Category == "pii" || f.Category == "secrets") && action == "allow" {
				action = "redact"
			}
		}

		resp := CheckResponse{
			Allowed:   allowed,
			Action:    action,
			Findings:  findings,
			Redacted:  redacted,
			LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
		}

		// Marshal first so we can attribute byte_count_out to the event,
		// then write. writeJSON is bypassed here because we need the size.
		body, mErr := json.Marshal(resp)
		if mErr != nil {
			slog.ErrorContext(r.Context(), "marshal response", "err", mErr)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encode failed"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		bytesOut, _ := w.Write(body)

		entry, ok := entryFromCtx(r.Context())
		if !ok {
			// Should never happen — auth() always attaches Entry on success.
			// If it does, the request was somehow let through without auth;
			// log loud and skip the emit (we have no org to attribute to).
			slog.ErrorContext(r.Context(), "metering: no entry in context — skipping emit")
			return
		}
		metering.Emit(Event{
			OrgID:       entry.OrgID,
			ProjectID:   entry.ProjectID,
			KeyID:       entry.KeyID,
			Action:      action,
			Categories:  findingCategories(findings),
			Rules:       findingRules(findings),
			Pairs:       findingPairs(findings),
			LatencyMs:   resp.LatencyMs,
			InferenceMs: float64(inferenceDur.Microseconds()) / 1000.0,
			Status:      http.StatusOK,
			BytesIn:     bytesIn,
			BytesOut:    bytesOut,
		})
	}
}

// findingCategories deduplicates the category set across findings — kept
// small (3 categories today) so a slice is fine.
func findingCategories(fs []Finding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if _, dup := seen[f.Category]; dup {
			continue
		}
		seen[f.Category] = struct{}{}
		out = append(out, f.Category)
	}
	return out
}

// findingRules deduplicates the rule set; cardinality bounded by the rule
// catalog (~20).
func findingRules(fs []Finding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if _, dup := seen[f.Rule]; dup {
			continue
		}
		seen[f.Rule] = struct{}{}
		out = append(out, f.Rule)
	}
	return out
}

// findingPairs deduplicates (rule, category) pairs on rule name, keeping
// the first occurrence's category. The analytics rollup needs the
// rule→category mapping inline so the aggregator doesn't have to know the
// rule catalog (which lives in this repo, not in veto-cloud).
func findingPairs(fs []Finding) []FindingPair {
	seen := map[string]struct{}{}
	out := make([]FindingPair, 0, len(fs))
	for _, f := range fs {
		if _, dup := seen[f.Rule]; dup {
			continue
		}
		seen[f.Rule] = struct{}{}
		out = append(out, FindingPair{Rule: f.Rule, Category: f.Category})
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
