package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Static-key mode lets the open-source gateway run without veto-cloud (or
// any control-plane RPC). Set VETO_STATIC_KEYS to a comma-separated list
// of `<plaintext>:<org_id>:<tier>` triples and the gateway resolves keys
// from that list instead of looking them up in Redis / cloud. Redis +
// metering remain optional in this mode.
//
// Trade-offs vs the dynamic (managed) path:
//   - No argon2id (the env var IS the source of truth; if it leaks, you
//     have a bigger problem than a verify bypass).
//   - No revocation — restart the gateway with an updated env to "revoke".
//   - No per-key metering history (static-mode gateways are likely solo
//     deployments; if you need history, run veto-cloud or BYO equivalent).
//   - Rate-limit still works for the "free" tier hard cap (10k/mo from
//     veto-core/config/tiers.json) when Redis is provided; otherwise it
//     fails open.
//
// Example:
//   VETO_STATIC_KEYS=vt_live_abcde…:my-org:free,vt_live_fghij…:my-org:pro

const (
	staticEntryFields = 3 // key:org:tier
	staticEntrySep    = ","
	staticFieldSep    = ":"
)

// parseStaticKeys turns the env-var string into a plaintext-keyed map.
// Empty input returns nil, nil — the caller treats that as "static mode
// disabled, fall back to dynamic lookup". Any parse error is fatal at
// boot: a malformed VETO_STATIC_KEYS would silently lock out the
// operator if we ignored the bad entries.
func parseStaticKeys(raw string) (map[string]Entry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make(map[string]Entry)
	periodStart := time.Now().UTC().Truncate(24 * time.Hour)
	for periodStart.Day() != 1 {
		periodStart = periodStart.AddDate(0, 0, -1)
	}

	entries := strings.Split(raw, staticEntrySep)
	for i, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		parts := strings.Split(e, staticFieldSep)
		if len(parts) != staticEntryFields {
			return nil, fmt.Errorf("VETO_STATIC_KEYS entry %d: expected %d colon-separated fields, got %d",
				i+1, staticEntryFields, len(parts))
		}
		plaintext := strings.TrimSpace(parts[0])
		orgID := strings.TrimSpace(parts[1])
		tier := strings.TrimSpace(parts[2])

		if _, _, ok := parseAPIKey(plaintext); !ok {
			return nil, fmt.Errorf("VETO_STATIC_KEYS entry %d: plaintext key must match %s<52 base32 chars>",
				i+1, keyPrefixLive)
		}
		if orgID == "" {
			return nil, fmt.Errorf("VETO_STATIC_KEYS entry %d: org_id required", i+1)
		}
		if tier != "free" && tier != "pro" && tier != "enterprise" {
			return nil, fmt.Errorf("VETO_STATIC_KEYS entry %d: tier must be free|pro|enterprise, got %q",
				i+1, tier)
		}
		if _, dup := out[plaintext]; dup {
			return nil, fmt.Errorf("VETO_STATIC_KEYS entry %d: duplicate plaintext key", i+1)
		}
		out[plaintext] = Entry{
			KeyID:              "static-" + shortHash(plaintext),
			ProjectID:          "static-" + orgID,
			OrgID:              orgID,
			Tier:               tier,
			HashArgon2id:       "", // unused in static mode
			CurrentPeriodStart: periodStart.Unix(),
		}
	}

	if len(out) == 0 {
		return nil, errors.New("VETO_STATIC_KEYS set but produced zero entries — check the format")
	}
	return out, nil
}

// shortHash gives each static key a stable, non-reversible id for logs +
// metering events without exposing the plaintext. First 12 hex chars of
// SHA-256 is plenty (collision odds negligible at the static-list scale).
func shortHash(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])[:12]
}
