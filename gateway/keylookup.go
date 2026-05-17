package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/veto-guardrails/veto-core/config"
	"golang.org/x/crypto/argon2"
)

// keyPrefixLive is the only prefix accepted at v1. vt_test_ is reserved.
const keyPrefixLive = "vt_live_"

// keyTotalLen — "vt_live_" (8) + base32-no-padding of 32 random bytes (52).
// Hard-bounded so a malformed header never reaches argon2id.
const keyTotalLen = len(keyPrefixLive) + 52

// last4Len mirrors what cloud stores at mint time.
const last4Len = 4

// ErrKeyNotFound — the supplied key has no active row in cloud's api_keys.
var ErrKeyNotFound = errors.New("key not found")

// Entry is a local alias for the cross-repo cache wire format defined in
// veto-core/config. Aliasing (not redefining) so the gateway and cloud
// can never disagree on the JSON shape — the struct lives once, in
// config.KeyCacheEntry. Existing call-sites continue using the short
// `Entry` name.
type Entry = config.KeyCacheEntry

// Lookup resolves customer keys: Redis cache first, cloud RPC on miss. No
// LRU yet — Lot D layers an in-process cache on top so argon2id verification
// runs once per minute per key, not once per request.
type Lookup struct {
	rdb      *redis.Client
	cloudURL string
	cloudTok string
	httpc    *http.Client
}

func newLookup(redisURL, cloudURL, cloudTok string) (*Lookup, error) {
	if redisURL == "" {
		return nil, errors.New("VETO_REDIS_URL required")
	}
	if cloudURL == "" {
		return nil, errors.New("VETO_CLOUD_URL required")
	}
	if cloudTok == "" {
		return nil, errors.New("VETO_CLOUD_INTERNAL_TOKEN required")
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
	return &Lookup{
		rdb:      rdb,
		cloudURL: strings.TrimRight(cloudURL, "/"),
		cloudTok: cloudTok,
		httpc: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}, nil
}

func (l *Lookup) Close() error {
	if l == nil || l.rdb == nil {
		return nil
	}
	return l.rdb.Close()
}

// Resolve returns the cached or freshly-fetched entry for prefix+last4.
// Order: Redis GET → cloud RPC fallback → ErrKeyNotFound. Redis transport
// errors fall through to RPC so a Redis blip can't lock customers out.
func (l *Lookup) Resolve(ctx context.Context, prefix, last4 string) (Entry, error) {
	val, err := l.rdb.Get(ctx, config.KeyCachePrefix+prefix+last4).Bytes()
	if err == nil {
		var e Entry
		if jerr := json.Unmarshal(val, &e); jerr == nil {
			return e, nil
		}
		// Bad payload in Redis — treat as miss and re-warm via RPC.
	}
	return l.rpcLookup(ctx, prefix, last4)
}

func (l *Lookup) rpcLookup(ctx context.Context, prefix, last4 string) (Entry, error) {
	u := l.cloudURL + "/internal/v1/keys/lookup?prefix=" + prefix + "&last4=" + last4
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return Entry{}, err
	}
	req.Header.Set("Authorization", "Bearer "+l.cloudTok)
	resp, err := l.httpc.Do(req)
	if err != nil {
		return Entry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Entry{}, ErrKeyNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return Entry{}, fmt.Errorf("cloud lookup status %d", resp.StatusCode)
	}
	var e Entry
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// parseAPIKey extracts (prefix, last4) from a presented key. Validates length
// and the live prefix so a malformed header never reaches argon2id (which is
// expensive enough to be worth gating).
func parseAPIKey(k string) (prefix, last4 string, ok bool) {
	if len(k) != keyTotalLen || !strings.HasPrefix(k, keyPrefixLive) {
		return "", "", false
	}
	return keyPrefixLive, k[len(k)-last4Len:], true
}

// argonVerify recomputes argon2id with the parameters embedded in the stored
// PHC string, then constant-time compares. Returns false (no error) on
// mismatch; only returns error on malformed PHC (a corruption bug, not user
// input).
func argonVerify(plaintext, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	// Expect: ["", "argon2id", "v=19", "m=…,t=…,p=…", "<salt>", "<key>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid phc format")
	}
	if parts[2] != "v=19" {
		return false, fmt.Errorf("unsupported argon version: %s", parts[2])
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("parse argon params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode key: %w", err)
	}
	got := argon2.IDKey([]byte(plaintext), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
