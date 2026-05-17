module veto-gateway

go 1.23

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/redis/go-redis/v9 v9.7.0
	github.com/veto-guardrails/veto-core/config v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.27.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/sys v0.25.0 // indirect
)

// Sibling-module replace: gateway and config live in the same git repo
// but use separate go.mods (no top-level module at veto-core root). This
// makes the local source the build dependency — no version dance.
replace github.com/veto-guardrails/veto-core/config => ../config
