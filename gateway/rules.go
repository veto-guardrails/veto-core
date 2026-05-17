package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/veto-guardrails/veto-core/config"
)

// patternRule binds the cross-repo catalog entry (config.RuleMeta) to
// the gateway-only compiled regex and replacement template. The split
// keeps name/category/severity in veto-core/config (shared with cloud)
// while leaving the regex literals here where they belong.
type patternRule struct {
	meta    config.RuleMeta
	re      *regexp.Regexp
	replace string
}

// patternByName maps catalog rule name → (regex, replacement). Every
// entry in config.Rules MUST have a matching entry here; init() panics
// otherwise so drift is caught at boot rather than producing silent
// missing-finding incidents.
var patternByName = map[string]struct {
	re      *regexp.Regexp
	replace string
}{
	"private_key": {
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----`),
		"[REDACTED_PRIVATE_KEY]",
	},
	"jwt": {
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
		"[REDACTED_JWT]",
	},
	"aws_access_key": {
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"[REDACTED_AWS_KEY]",
	},
	"openai_key": {
		regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`),
		"[REDACTED_OPENAI_KEY]",
	},
	"anthropic_key": {
		regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
		"[REDACTED_ANTHROPIC_KEY]",
	},
	"github_pat": {
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b`),
		"[REDACTED_GH_TOKEN]",
	},

	"email": {
		regexp.MustCompile(`[\w.+\-]+@[\w\-]+\.[\w.\-]{2,}`),
		"[REDACTED_EMAIL]",
	},
	"iban": {
		regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
		"[REDACTED_IBAN]",
	},
	"nir_fr": {
		regexp.MustCompile(`\b[12]\s?\d{2}\s?\d{2}\s?(?:2[AB]|\d{2})\s?\d{3}\s?\d{3}\s?\d{2}\b`),
		"[REDACTED_NIR]",
	},
	"ssn_us": {
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		"[REDACTED_SSN]",
	},
	"credit_card": {
		regexp.MustCompile(`\b(?:\d{4}[ \-]){3}\d{3,4}\b|\b\d{15,16}\b`),
		"[REDACTED_CC]",
	},
	"phone_fr": {
		regexp.MustCompile(`\b(?:\+33[ .\-]?|0)[67](?:[ .\-]?\d{2}){4}\b`),
		"[REDACTED_PHONE]",
	},
	"phone_intl": {
		regexp.MustCompile(`\+\d{1,3}[ .\-]?\d{1,4}[ .\-]?\d{2,4}[ .\-]?\d{2,4}(?:[ .\-]?\d{2,4})?`),
		"[REDACTED_PHONE]",
	},
}

var rules []patternRule

func init() {
	rules = make([]patternRule, 0, len(config.Rules))
	for _, meta := range config.Rules {
		p, ok := patternByName[meta.Name]
		if !ok {
			panic(fmt.Sprintf("gateway: catalog declares rule %q but no regex pattern is wired", meta.Name))
		}
		rules = append(rules, patternRule{meta: meta, re: p.re, replace: p.replace})
	}
	for name := range patternByName {
		if _, ok := config.RuleByName(name); !ok {
			panic(fmt.Sprintf("gateway: regex %q has no catalog entry in config.Rules", name))
		}
	}
}

func scanCategory(text, category string) ([]Finding, string) {
	findings := []Finding{}
	redacted := text
	for _, rule := range rules {
		if rule.meta.Category != category {
			continue
		}
		matches := rule.re.FindAllStringIndex(redacted, -1)
		if len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			findings = append(findings, Finding{
				Category: rule.meta.Category,
				Rule:     rule.meta.Name,
				Severity: rule.meta.Severity,
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
