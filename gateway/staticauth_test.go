package main

import (
	"strings"
	"testing"
)

// validKey is a properly formatted vt_live_… plaintext (8-char prefix + 52
// base32 chars = 60 chars total). Real keys are 32 random bytes base32'd,
// but parseAPIKey only checks length + prefix.
const validKey = "vt_live_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

func TestParseStaticKeys_Empty(t *testing.T) {
	out, err := parseStaticKeys("")
	if err != nil {
		t.Fatalf("empty: unexpected err %v", err)
	}
	if out != nil {
		t.Errorf("empty: expected nil map, got %v", out)
	}
}

func TestParseStaticKeys_Single(t *testing.T) {
	raw := validKey + ":my-org:free"
	out, err := parseStaticKeys(raw)
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("single: expected 1 entry, got %d", len(out))
	}
	e := out[validKey]
	if e.OrgID != "my-org" {
		t.Errorf("OrgID: got %q, want %q", e.OrgID, "my-org")
	}
	if e.Tier != "free" {
		t.Errorf("Tier: got %q, want %q", e.Tier, "free")
	}
	if !strings.HasPrefix(e.KeyID, "static-") {
		t.Errorf("KeyID: expected static- prefix, got %q", e.KeyID)
	}
	if e.HashArgon2id != "" {
		t.Errorf("HashArgon2id: expected empty in static mode, got %q", e.HashArgon2id)
	}
	if e.CurrentPeriodStart == 0 {
		t.Errorf("CurrentPeriodStart: expected non-zero unix, got 0")
	}
}

func TestParseStaticKeys_Multiple(t *testing.T) {
	key2 := "vt_live_zyxwvutsrqponmlkjihgfedcba234567abcdefghijklmnopqrst"
	raw := validKey + ":alice-org:free, " + key2 + " :bob-org:pro"
	out, err := parseStaticKeys(raw)
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("multi: expected 2 entries, got %d", len(out))
	}
	if out[validKey].OrgID != "alice-org" || out[validKey].Tier != "free" {
		t.Errorf("entry 1: %+v", out[validKey])
	}
	if out[key2].OrgID != "bob-org" || out[key2].Tier != "pro" {
		t.Errorf("entry 2: %+v", out[key2])
	}
}

func TestParseStaticKeys_BadFieldCount(t *testing.T) {
	cases := []string{
		validKey + ":only-two-fields",
		validKey + ":org:tier:extra",
		"::",
	}
	for _, raw := range cases {
		if _, err := parseStaticKeys(raw); err == nil {
			t.Errorf("expected error for %q, got nil", raw)
		}
	}
}

func TestParseStaticKeys_BadPrefix(t *testing.T) {
	// Bogus prefix `xx_live_` deliberately avoids any real provider's API
	// key shape — `sk_live_` would trip GitHub's Stripe secret scanner on
	// push protection, even though this is a negative-test fixture.
	cases := []string{
		"xx_live_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst:org:free", // wrong prefix
		"vt_test_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst:org:free", // vt_test_ reserved
		"vt_live_short:org:free",                                              // too short
	}
	for _, raw := range cases {
		if _, err := parseStaticKeys(raw); err == nil {
			t.Errorf("expected error for %q, got nil", raw)
		}
	}
}

func TestParseStaticKeys_BadTier(t *testing.T) {
	if _, err := parseStaticKeys(validKey + ":org:premium"); err == nil {
		t.Error("expected error for unknown tier 'premium'")
	}
	if _, err := parseStaticKeys(validKey + ":org:"); err == nil {
		t.Error("expected error for empty tier")
	}
}

func TestParseStaticKeys_EmptyOrg(t *testing.T) {
	if _, err := parseStaticKeys(validKey + "::free"); err == nil {
		t.Error("expected error for empty org_id")
	}
}

func TestParseStaticKeys_Duplicate(t *testing.T) {
	raw := validKey + ":a:free," + validKey + ":b:pro"
	if _, err := parseStaticKeys(raw); err == nil {
		t.Error("expected error for duplicate plaintext")
	}
}
