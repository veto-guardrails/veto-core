package main

import (
	"regexp"
	"strings"
)

type patternRule struct {
	name     string
	category string
	severity string
	re       *regexp.Regexp
	replace  string
}

var rules = []patternRule{
	{"private_key", "secrets", "high",
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----`),
		"[REDACTED_PRIVATE_KEY]"},
	{"jwt", "secrets", "medium",
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
		"[REDACTED_JWT]"},
	{"aws_access_key", "secrets", "high",
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"[REDACTED_AWS_KEY]"},
	{"openai_key", "secrets", "high",
		regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`),
		"[REDACTED_OPENAI_KEY]"},
	{"anthropic_key", "secrets", "high",
		regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
		"[REDACTED_ANTHROPIC_KEY]"},
	{"github_pat", "secrets", "high",
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b`),
		"[REDACTED_GH_TOKEN]"},

	{"email", "pii", "medium",
		regexp.MustCompile(`[\w.+\-]+@[\w\-]+\.[\w.\-]{2,}`),
		"[REDACTED_EMAIL]"},
	{"iban", "pii", "high",
		regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
		"[REDACTED_IBAN]"},
	{"nir_fr", "pii", "high",
		regexp.MustCompile(`\b[12]\s?\d{2}\s?\d{2}\s?(?:2[AB]|\d{2})\s?\d{3}\s?\d{3}\s?\d{2}\b`),
		"[REDACTED_NIR]"},
	{"ssn_us", "pii", "high",
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		"[REDACTED_SSN]"},
	{"credit_card", "pii", "high",
		regexp.MustCompile(`\b(?:\d{4}[ \-]){3}\d{3,4}\b|\b\d{15,16}\b`),
		"[REDACTED_CC]"},
	{"phone_fr", "pii", "medium",
		regexp.MustCompile(`\b(?:\+33[ .\-]?|0)[67](?:[ .\-]?\d{2}){4}\b`),
		"[REDACTED_PHONE]"},
	{"phone_intl", "pii", "medium",
		regexp.MustCompile(`\+\d{1,3}[ .\-]?\d{1,4}[ .\-]?\d{2,4}[ .\-]?\d{2,4}(?:[ .\-]?\d{2,4})?`),
		"[REDACTED_PHONE]"},
}

func scanCategory(text, category string) ([]Finding, string) {
	findings := []Finding{}
	redacted := text
	for _, rule := range rules {
		if rule.category != category {
			continue
		}
		// Single pass: capture each match's bounds *and* emit the replacement
		// in one walk. Indices refer to the pre-redaction `redacted` string,
		// matching the contract the previous two-pass version exposed.
		matches := rule.re.FindAllStringIndex(redacted, -1)
		if len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			findings = append(findings, Finding{
				Category: rule.category,
				Rule:     rule.name,
				Severity: rule.severity,
				Match:    redacted[m[0]:m[1]],
				Start:    m[0],
				End:      m[1],
			})
		}
		var b strings.Builder
		b.Grow(len(redacted))
		prev := 0
		for _, m := range matches {
			b.WriteString(redacted[prev:m[0]])
			b.WriteString(rule.replace)
			prev = m[1]
		}
		b.WriteString(redacted[prev:])
		redacted = b.String()
	}
	return findings, redacted
}
