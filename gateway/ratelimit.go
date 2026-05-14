package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Per-IP token bucket. Interim defense on the only public surface (/v1/check)
// until a Redis-backed per-key limiter lands with the metering pipeline (SPEC
// §4.5 + §4.8). Memory bounded by a small GC pass that evicts buckets idle
// past idleTTL.
//
// Defaults sized for a single Hetzner box and a shared dev key: 60 req/min
// per IP with a burst of 20. Override via VETO_RATE_RPS / VETO_RATE_BURST.

type bucket struct {
	tokens float64
	last   time.Time
}

type ipLimiter struct {
	mu       sync.Mutex
	rps      float64
	burst    float64
	idleTTL  time.Duration
	buckets  map[string]*bucket
}

func newIPLimiter(rps, burst float64) *ipLimiter {
	l := &ipLimiter{
		rps:     rps,
		burst:   burst,
		idleTTL: 10 * time.Minute,
		buckets: make(map[string]*bucket),
	}
	go l.gcLoop()
	return l
}

func (l *ipLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *ipLimiter) gcLoop() {
	t := time.NewTicker(l.idleTTL)
	for range t.C {
		cutoff := time.Now().Add(-l.idleTTL)
		l.mu.Lock()
		for k, b := range l.buckets {
			if b.last.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// clientIP returns the most trusted source IP available. Caddy in front sets
// X-Real-IP from Cloudflare's CF-Connecting-IP for the /v1/* route. If that
// header is absent (direct hit, local dev), fall back to RemoteAddr.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func rateLimit(l *ipLimiter) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !l.allow(clientIP(r), time.Now()) {
				w.Header().Set("Retry-After", "1")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
				return
			}
			next(w, r)
		}
	}
}
