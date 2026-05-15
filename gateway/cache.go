package main

import (
	"crypto/sha256"
	"time"

	expirable "github.com/hashicorp/golang-lru/v2/expirable"
)

// Verified-key LRU. Keyed by sha256(plaintext) so a hit means the plaintext
// has already cleared the argon2id verify within the TTL — auth() can skip
// both the Redis/RPC lookup and the ~50ms hash on hot keys. Sized for ~1k
// distinct active keys per box; oldest evicted on overflow.
const (
	verifiedCacheSize = 1024
	verifiedCacheTTL  = 60 * time.Second
)

type verifiedCache struct {
	c *expirable.LRU[[32]byte, Entry]
}

func newVerifiedCache() *verifiedCache {
	return &verifiedCache{
		c: expirable.NewLRU[[32]byte, Entry](verifiedCacheSize, nil, verifiedCacheTTL),
	}
}

func (v *verifiedCache) Get(plaintext string) (Entry, bool) {
	return v.c.Get(sha256.Sum256([]byte(plaintext)))
}

func (v *verifiedCache) Put(plaintext string, e Entry) {
	v.c.Add(sha256.Sum256([]byte(plaintext)), e)
}
