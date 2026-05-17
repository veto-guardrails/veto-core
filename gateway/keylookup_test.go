package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/veto-guardrails/veto-core/config"
)

// makeHash mints a PHC string with the supplied params, mirroring the
// shape veto-cloud writes. Tiny duplicate of veto-cloud's argonHash so
// the gateway tests stay self-contained.
func makeHash(plaintext string, m, t uint32, p uint8) string {
	salt := []byte("0123456789abcdef") // fixed for determinism
	key := argon2.IDKey([]byte(plaintext), salt, t, m, p, 32)
	return strings.Join([]string{
		"",
		"argon2id",
		"v=19",
		// Sprintf without fmt — avoid the import; %d via fmt would be cleaner but unimportant
		"m=" + itoa(int(m)) + ",t=" + itoa(int(t)) + ",p=" + itoa(int(p)),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	}, "$")
}

// itoa: stdlib-light integer→string conversion for the test helper above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestArgonVerify_HappyPath(t *testing.T) {
	plaintext := "vt_live_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr"
	hash := makeHash(plaintext, config.MinArgon2idMemoryKiB, config.MinArgon2idTime, config.MinArgon2idThreads)

	ok, err := argonVerify(plaintext, hash)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !ok {
		t.Error("verify returned false for a freshly-made hash")
	}
}

func TestArgonVerify_FloorRejectsWeakHash(t *testing.T) {
	plaintext := "vt_live_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr"
	// Memory cost below the floor — attacker-controlled mint would produce
	// this. Verify must refuse even though the hash is otherwise valid.
	weak := makeHash(plaintext, 8, config.MinArgon2idTime, config.MinArgon2idThreads)

	_, err := argonVerify(plaintext, weak)
	if err == nil {
		t.Fatal("expected floor-violation error, got nil")
	}
	if !strings.Contains(err.Error(), "below floor") {
		t.Errorf("expected 'below floor' in error, got %q", err)
	}
}

func TestArgonVerify_FloorRejectsLowTime(t *testing.T) {
	plaintext := "vt_live_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr"
	// argon2.IDKey panics on t=0 ("number of rounds too small"), so we
	// hand-construct a PHC string claiming t=0 instead of running makeHash.
	// argonVerify rejects on the floor check (line 163) before re-computing
	// argon2id, so the salt/key bodies don't need to be meaningful.
	weak := "$argon2id$v=19$m=" + itoa(int(config.MinArgon2idMemoryKiB)) +
		",t=0,p=" + itoa(int(config.MinArgon2idThreads)) +
		"$MDEyMzQ1Njc4OWFiY2RlZg" + // base64("0123456789abcdef")
		"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 zero bytes

	_, err := argonVerify(plaintext, weak)
	if err == nil {
		t.Fatal("expected floor-violation error for t=0, got nil")
	}
}

func TestArgonVerify_MalformedRejects(t *testing.T) {
	cases := []string{
		"",                                         // empty
		"$argon2id$v=19$m=64,t=1,p=2$abc",          // missing last field
		"$sha256$v=19$m=64,t=1,p=2$abc$def",        // wrong algo
		"$argon2id$v=18$m=64,t=1,p=2$abc$def",      // wrong version
		"$argon2id$v=19$bogus-params$abc$def",      // unparseable params
	}
	for _, phc := range cases {
		if _, err := argonVerify("anything", phc); err == nil {
			t.Errorf("expected error for %q, got nil", phc)
		}
	}
}
