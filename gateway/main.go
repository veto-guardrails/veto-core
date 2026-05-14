package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
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
	apiKey = os.Getenv("VETO_API_KEY")
	if apiKey == "" {
		log.Fatal("VETO_API_KEY is required")
	}
	if apiKey == devAPIKey && os.Getenv("VETO_ALLOW_DEV_KEY") != "1" {
		log.Fatal("VETO_API_KEY is set to the public dev sentinel; set a real key or VETO_ALLOW_DEV_KEY=1 for local dev")
	}
	inferenceURL = envDefault("VETO_INFERENCE_URL", "http://inference:8000")

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(10 * time.Second))

	r.Get("/healthz", healthz)
	r.Post("/v1/check", auth(handleCheck))

	addr := ":8080"
	log.Printf("veto-gateway v0.1 listening on %s, inference=%s", addr, inferenceURL)
	log.Fatal(http.ListenAndServe(addr, r))
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
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
				log.Printf("inference error: %v", err)
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
