package config

// Rule catalog — single source of truth for the (name, category, severity)
// triples the gateway emits in findings and the cloud aggregator persists
// in usage_rollups_rules.
//
// The catalog metadata lives here so cloud + gateway agree on the rule
// universe without the gateway shipping its private regex literals to
// veto-cloud. Patterns + replacement strings remain in
// veto-core/gateway/rules.go, tied to catalog entries by Name. The
// gateway panics at init if the two sets drift.
//
// Order matters: the gateway scans rules in the declared order within a
// category, so earlier entries take precedence when matches overlap.
// Secrets are listed before PII because we want sk-/ghp- patterns
// redacted before the PII pass starts (e.g. an OpenAI key inside a JSON
// payload shouldn't trip the credit-card regex on its digits).

type RuleMeta struct {
	Name     string
	Category string
	Severity string
}

var Rules = []RuleMeta{
	{Name: "private_key", Category: "secrets", Severity: "high"},
	{Name: "jwt", Category: "secrets", Severity: "medium"},
	{Name: "aws_access_key", Category: "secrets", Severity: "high"},
	{Name: "openai_key", Category: "secrets", Severity: "high"},
	{Name: "anthropic_key", Category: "secrets", Severity: "high"},
	{Name: "github_pat", Category: "secrets", Severity: "high"},

	{Name: "email", Category: "pii", Severity: "medium"},
	{Name: "iban", Category: "pii", Severity: "high"},
	{Name: "nir_fr", Category: "pii", Severity: "high"},
	{Name: "ssn_us", Category: "pii", Severity: "high"},
	{Name: "credit_card", Category: "pii", Severity: "high"},
	{Name: "phone_fr", Category: "pii", Severity: "medium"},
	{Name: "phone_intl", Category: "pii", Severity: "medium"},
}

// RuleByName returns the catalog entry for a given rule name. The bool
// is false for unknown names — useful at the aggregator to detect
// gateway↔cloud version drift.
func RuleByName(name string) (RuleMeta, bool) {
	for _, r := range Rules {
		if r.Name == name {
			return r, true
		}
	}
	return RuleMeta{}, false
}
