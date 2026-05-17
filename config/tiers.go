// Package config exposes the cross-repo Veto configuration as typed Go
// accessors. The canonical source is tiers.json (sibling file) — every
// consumer (gateway, cloud, web) reads from this one file via:
//   - veto-core/gateway: imports this package directly (replace ../config)
//   - veto-cloud:        submodules veto-core at vendor/veto-core, imports
//                        this package with replace → ./vendor/veto-core/config
//   - veto-web:          imports tiers.json directly via TypeScript
//
// Drift hazard collapses to one file. If tiers.json changes, all three
// consumers see the new value on next build (Go) / bundle (web). The
// submodule pointer bump is the deploy gate.
package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed tiers.json
var tiersJSON []byte

// Tier carries the per-plan numbers used at the gateway, the dashboard,
// the analytics-rollups retention cron, and (in spirit) the Stripe price
// configuration. Nullable fields use pointers so JSON null is
// distinguishable from 0.
type Tier struct {
	Name                    string   `json:"name"`
	MonthlyRequestsLimit    *int64   `json:"monthly_requests_limit"`
	MonthlyRequestsIncluded *int64   `json:"monthly_requests_included"`
	BasePriceEUR            *float64 `json:"base_price_eur"`
	OveragePerMillionEUR    *float64 `json:"overage_per_million_eur"`
	// RollupsRetentionDays — how long usage_rollups_* rows are kept for
	// this tier. SPEC §4.14 retention matrix. The cron in veto-cloud
	// reads this; 0 / missing means "keep forever" (not used today —
	// every shipping tier has an explicit value).
	RollupsRetentionDays int `json:"rollups_retention_days"`
}

var tiers map[string]Tier

func init() {
	if err := json.Unmarshal(tiersJSON, &tiers); err != nil {
		panic(fmt.Sprintf("config: tiers.json malformed: %v", err))
	}
	for _, name := range []string{"free", "pro", "enterprise"} {
		if _, ok := tiers[name]; !ok {
			panic(fmt.Sprintf("config: tiers.json missing %q entry", name))
		}
	}
}

// ByName returns the Tier struct for a given tier name. Unknown names
// return the zero Tier (Name == ""). Callers can branch on Name == "" if
// the distinction matters.
func ByName(name string) Tier {
	return tiers[name]
}

// FreeMonthlyLimit is the hard cap enforced by the gateway and displayed
// by the dashboard for the Free tier. Returns 0 if the JSON marks Free
// as unlimited (it shouldn't — fail loud in that case).
func FreeMonthlyLimit() int64 {
	t := tiers["free"]
	if t.MonthlyRequestsLimit == nil {
		panic("config: free tier must have a monthly_requests_limit")
	}
	return *t.MonthlyRequestsLimit
}

// ProIncludedQuota is the requests-included-before-overage threshold for
// Pro. Used by the dashboard usage panel; the gateway tracks but does
// NOT enforce a Pro cap (overage bills via Stripe Meter).
func ProIncludedQuota() int64 {
	t := tiers["pro"]
	if t.MonthlyRequestsIncluded == nil {
		panic("config: pro tier must have a monthly_requests_included")
	}
	return *t.MonthlyRequestsIncluded
}

// LimitForTier returns the hard-cap monthly request count for a tier, or
// 0 if the tier has no hard cap (Pro, Enterprise). Mirrors gateway
// enforcement semantics: 0 means "fail open / no 429".
func LimitForTier(tier string) int64 {
	t := tiers[tier]
	if t.MonthlyRequestsLimit == nil {
		return 0
	}
	return *t.MonthlyRequestsLimit
}

// IncludedQuotaForTier returns the "before overage" count for a tier,
// or 0 if not applicable. Used by the dashboard for the progress bar
// numerator.
func IncludedQuotaForTier(tier string) int64 {
	t := tiers[tier]
	if t.MonthlyRequestsIncluded == nil {
		return 0
	}
	return *t.MonthlyRequestsIncluded
}

// RetentionDaysForTier returns how many days of usage_rollups_* rows to
// keep for a given tier. 0 means "keep forever" — used by the retention
// cron in veto-cloud as the cutoff = now - N days.
func RetentionDaysForTier(tier string) int {
	return tiers[tier].RollupsRetentionDays
}
