package config

// KeyCacheEntry is the gateway's view of an API-key lookup result, also
// the wire format cloud writes into Redis at `KeyCachePrefix+prefix+last4`.
// Defined here (in veto-core/config) so the gateway and cloud are
// guaranteed to encode + decode the same bytes — drift on either side
// produces an unauthenticated lookup, which is loud.
//
// JSON tags are normative: they're the Redis payload contract and the
// JSON shape of the /internal/v1/keys/lookup response.
//
// CurrentPeriodStart is unix-seconds of the org's current billing-period
// start (Stripe period for Pro/Enterprise, synthetic anniversary for
// Free). Used by the gateway as the namespace component of the rate-limit
// Redis key so the counter resets on period rollover.
type KeyCacheEntry struct {
	KeyID              string `json:"key_id"`
	ProjectID          string `json:"project_id"`
	OrgID              string `json:"org_id"`
	Tier               string `json:"tier"`
	HashArgon2id       string `json:"hash_argon2id"`
	CurrentPeriodStart int64  `json:"current_period_start"`
}

// KeyCachePrefix namespaces the Redis keys cloud writes and the gateway
// reads. Format: `KeyCachePrefix + prefix + last4`, e.g.
// "veto:key:vt_live_abcd". Changing this value requires flushing every
// running gateway's verified-key LRU plus the Redis keyspace.
const KeyCachePrefix = "veto:key:"

// Argon2id parameter floor — minimum-acceptable values when verifying a
// stored hash. Mint paths (veto-cloud/internal/server/apikeys.go) use
// these or higher; verify paths (veto-core/gateway/keylookup.go) reject
// anything below.
//
// Why this matters: argonVerify reads parameters from the stored PHC
// string and re-hashes with the same params. Without a floor, an
// attacker who compromises the mint code path could create
// intentionally-weak hashes (e.g. m=1 KiB, t=1) that still pass
// verification. Enforcing the floor at verify makes downgrade attacks
// loud — they fail the check instead of silently auth'ing.
//
// Current values match OWASP's 2024 recommendation for interactive
// logins. Raising the floor invalidates existing hashes — the cloud's
// reseed step would need to re-mint them.
const (
	MinArgon2idMemoryKiB uint32 = 64 * 1024 // 64 MiB
	MinArgon2idTime      uint32 = 1
	MinArgon2idThreads   uint8  = 2
)
