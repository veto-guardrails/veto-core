package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
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

// devAPIKey is the sentinel shipped in compose defaults and docs. Refuse to
// boot in prod if VETO_API_KEY is empty or matches this value — a missing env
// shouldn't silently grant a known-public bypass.
const devAPIKey = "vt_test_dev_change_me"

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

var (
	apiKey       string
	inferenceURL string
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	apiKey = os.Getenv("VETO_API_KEY")
	if apiKey == "" {
		slog.Error("VETO_API_KEY is required")
		os.Exit(1)
	}
	if apiKey == devAPIKey && os.Getenv("VETO_ALLOW_DEV_KEY") != "1" {
		slog.Error("VETO_API_KEY is set to the public dev sentinel; set a real key or VETO_ALLOW_DEV_KEY=1 for local dev")
		os.Exit(1)
	}
	inferenceURL = envDefault("VETO_INFERENCE_URL", "http://inference:8000")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
	r.Post("/v1/check", rateLimit(limiter)(auth(handleCheck)))

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

func auth(next http.HandlerFunc) http.HandlerFunc {
	want := []byte(apiKey)
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Veto-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		// subtle.ConstantTimeCompare returns 0 if lengths differ — pad to avoid
		// leaking the configured key length to a network attacker probing
		// timing differences on a public surface.
		got := []byte(key)
		if len(got) != len(want) {
			got = make([]byte, len(want))
		}
		if subtle.ConstantTimeCompare(got, want) != 1 || key == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
			f, err := detectInjection(ctx, req.Text)
			cancel()
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
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
