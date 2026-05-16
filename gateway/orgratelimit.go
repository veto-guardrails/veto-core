package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Per-org rate-limiting on the hot path.
//
// Scope: today this enforces ONLY the Free-tier monthly cap. Pro and
// Enterprise have no per-org cap — Pro overage is billed via the Stripe
// Meter (no need to 429), Enterprise is unlimited by contract. The
// implementation still increments the counter for all tiers so the same
// Redis key namespace can carry "displayed usage vs Stripe billing" sanity
// checks if we ever need them.
//
// Tier limits mirror veto-cloud/internal/server/me_usage.go and SPEC §6.
// Keep both sides in lockstep; the dashboard panel and this enforcer must
// always agree on what "the limit" is.
const (
	freeMonthlyLimit int64 = 10_000
	proIncludedLimit int64 = 100_000 // soft target, not enforced; tracked only
	rlKeyPrefix            = "veto:rate:"
)

// rateLimitOpTimeout — each Redis op (INCR / EXPIRE) is short; cap so a
// stalled Redis can't pin a request handler.
const rateLimitOpTimeout = 500 * time.Millisecond

// OrgRateLimiter owns its own Redis client (per-concern separation, same
// pattern as the metering writer). Same Redis instance as the keycache
// and metering stream — we just hold a separate client so timeouts and
// pool sizing can be tuned per-concern.
type OrgRateLimiter struct {
	rdb *redis.Client
}

func newOrgRateLimiter(redisURL string) (*OrgRateLimiter, error) {
	if redisURL == "" {
		return nil, errors.New("VETO_REDIS_URL required")
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &OrgRateLimiter{rdb: rdb}, nil
}

func (rl *OrgRateLimiter) Close() error {
	if rl == nil || rl.rdb == nil {
		return nil
	}
	return rl.rdb.Close()
}

// rateKey namespaces the counter by org + period_start. A new period
// rolls over → new key → fresh 0 counter. Old key TTLs out (~32 days
// past creation) without operator intervention.
func rateKey(orgID string, periodStartUnix int64) string {
	return fmt.Sprintf("%s%s:%d", rlKeyPrefix, orgID, periodStartUnix)
}

// CheckAndIncrement atomically bumps the org's counter and returns:
//   - allowed: whether the request should proceed
//   - current: the post-increment count
//
// Fail-open: if Redis is down or any op errors, returns allowed=true with
// a logged warning. The displayed counter (PG) is authoritative for
// billing; a temporary enforcement gap is preferable to dropping paying
// traffic on a Redis hiccup.
func (rl *OrgRateLimiter) CheckAndIncrement(ctx context.Context, orgID, tier string, periodStartUnix int64) (bool, int64) {
	if rl == nil || rl.rdb == nil {
		return true, 0
	}
	limit := limitForTier(tier)

	opCtx, cancel := context.WithTimeout(ctx, rateLimitOpTimeout)
	defer cancel()

	key := rateKey(orgID, periodStartUnix)
	count, err := rl.rdb.Incr(opCtx, key).Result()
	if err != nil {
		slog.WarnContext(ctx, "ratelimit incr failed — failing open", "err", err, "org_id", orgID)
		return true, 0
	}
	// First INCR on a new key creates it with no TTL. Set EXPIRE only once
	// (Redis EXPIRE on an existing key with TTL is a no-op for GT/LT/etc.
	// flags; here we just always set a long TTL — idempotent enough).
	if count == 1 {
		// 35 days past period start: bigger than any monthly billing
		// period so the key never expires mid-cycle, but eventually
		// cleans up free orgs that churn.
		_ = rl.rdb.Expire(opCtx, key, 35*24*time.Hour).Err()
	}

	// Enforcement: only the Free tier has a hard cap. Pro/Enterprise see
	// no 429s — they're metered for overage.
	if limit > 0 && count > limit {
		return false, count
	}
	return true, count
}

// limitForTier returns the hard cap (>0) for tiers we enforce. 0 means
// "no hard cap" (Pro, Enterprise, or unknown — fail-open).
func limitForTier(tier string) int64 {
	switch tier {
	case "free":
		return freeMonthlyLimit
	default:
		return 0
	}
}

// orgRateLimit is the middleware. Must run AFTER auth so the resolved
// Entry is in context. Pulls org_id, tier, period_start from Entry — no
// extra round-trip to cloud.
func orgRateLimit(rl *OrgRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entry, ok := entryFromCtx(r.Context())
		if !ok {
			// auth didn't run, or its context didn't survive — defensive,
			// not expected. Let the request through; the absence of auth
			// is its own problem and would already have been caught.
			next(w, r)
			return
		}
		allowed, count := rl.CheckAndIncrement(r.Context(), entry.OrgID, entry.Tier, entry.CurrentPeriodStart)
		if !allowed {
			w.Header().Set("X-Veto-RateLimit-Limit", strconv.FormatInt(limitForTier(entry.Tier), 10))
			w.Header().Set("X-Veto-RateLimit-Used", strconv.FormatInt(count, 10))
			w.Header().Set("Retry-After", "3600") // hint: try again in an hour; not exact, but signals "wait, don't hammer"
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "monthly request cap reached",
				"limit": limitForTier(entry.Tier),
				"used":  count,
				"tier":  entry.Tier,
			})
			return
		}
		next(w, r)
	}
}
