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
