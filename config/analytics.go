package config

import "time"

// Analytics wire types for veto-cloud's GET /internal/v1/me/analytics.
//
// Declared here (in veto-core/config) so the TypeScript declaration that
// veto-web consumes can be generated from this single source of truth.
// Run `cd veto-core/config && tygo generate` after editing — the
// generated file lives at config/analytics.ts and is committed.
//
// JSON tags are normative: they are the wire payload customers see.
// Renaming a tag is a breaking change.

// AnalyticsResponse is the body returned by /internal/v1/me/analytics.
// veto-web aliases this as AnalyticsData for backward source compat.
type AnalyticsResponse struct {
	PeriodStart    time.Time         `json:"period_start"`
	PeriodEnd      time.Time         `json:"period_end"`
	TotalRequests  int64             `json:"total_requests"`
	Actions        ActionsBlock      `json:"actions"`
	Findings       []FindingCount    `json:"findings"`
	TotalFindings  int64             `json:"total_findings"`
	TopRules       []RuleCount       `json:"top_rules"`
	TotalRulesSeen int               `json:"total_rules_seen"`
	LatencyMs      LatencyPercentile `json:"latency_ms"`
	DailyVolume    []DayCount        `json:"daily_volume"`
}

type ActionsBlock struct {
	Allow  int64 `json:"allow"`
	Block  int64 `json:"block"`
	Redact int64 `json:"redact"`
}

type FindingCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type RuleCount struct {
	Rule     string `json:"rule"`
	Count    int64  `json:"count"`
	Category string `json:"category"`
}

type LatencyPercentile struct {
	P50 int `json:"p50"`
	P95 int `json:"p95"`
	P99 int `json:"p99"`
}

type DayCount struct {
	Date  string `json:"date"` // YYYY-MM-DD UTC
	Count int64  `json:"count"`
}
