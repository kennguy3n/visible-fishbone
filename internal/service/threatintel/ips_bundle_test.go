package threatintel

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func mustSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	return s
}

func sampleClaims() IPSRuleBundleClaims {
	return IPSRuleBundleClaims{
		SchemaVersion: IPSRuleSchemaVersion,
		Version:       7,
		Compiler:      "sng-control/threat-intel",
		RulesText:     `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"SNG THREATINTEL C2 ja3 client fingerprint"; ja3.hash; content:"e7d705a3286e19ea42f587b344ee6865"; classtype:command-and-control; sid:3200000000; rev:1;)` + "\n",
		Source:        IPSRuleSourceCustomOrg,
	}
}

// TestSignIPSRuleBundle_RoundTrip signs a bundle and verifies the
// envelope verifies+decodes back to the same claims under the pinned
// key, exercising the producer->edge happy path.
func TestSignIPSRuleBundle_RoundTrip(t *testing.T) {
	t.Parallel()
	s := mustSigner(t)
	claims := sampleClaims()

	env, err := s.SignIPSRuleBundle(claims)
	if err != nil {
		t.Fatalf("SignIPSRuleBundle: %v", err)
	}
	if env.Algorithm != Algorithm {
		t.Errorf("alg = %q, want %q", env.Algorithm, Algorithm)
	}
	if env.SigningKeyID != IPSSigningKeyID(s.Public()) {
		t.Errorf("signing_key_id = %q, want %q", env.SigningKeyID, IPSSigningKeyID(s.Public()))
	}
	if len(env.SigningKeyID) != 16 {
		t.Errorf("signing_key_id must be 16 hex chars, got %q", env.SigningKeyID)
	}

	got, err := env.VerifyWith(s.Public())
	if err != nil {
		t.Fatalf("VerifyWith: %v", err)
	}
	if got != claims {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, claims)
	}
}

// TestSignIPSRuleBundle_RejectsTamperAndWrongKey verifies the
// verify-before-decode posture: a tampered body or a non-pinned key
// fails with ErrSignatureMismatch and never yields claims.
func TestSignIPSRuleBundle_RejectsTamperAndWrongKey(t *testing.T) {
	t.Parallel()
	s := mustSigner(t)
	env, err := s.SignIPSRuleBundle(sampleClaims())
	if err != nil {
		t.Fatalf("SignIPSRuleBundle: %v", err)
	}

	// Wrong (non-pinned) key.
	other := mustSigner(t)
	if _, err := env.VerifyWith(other.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("verify under wrong key err = %v, want ErrSignatureMismatch", err)
	}

	// Tampered body: flip a byte, re-encode, keep the old signature.
	body, _, err := env.DecodedBody()
	if err != nil {
		t.Fatalf("DecodedBody: %v", err)
	}
	body[0] ^= 0xff
	tampered := env
	tampered.Body = base64.StdEncoding.EncodeToString(body)
	if _, err := tampered.VerifyWith(s.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("verify of tampered body err = %v, want ErrSignatureMismatch", err)
	}

	// Wrong algorithm label.
	badAlg := env
	badAlg.Algorithm = "rsa"
	if _, err := badAlg.VerifyWith(s.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("verify with bad alg err = %v, want ErrSignatureMismatch", err)
	}
}

// TestIPSRuleBundleBody_MsgpackShape pins the wire shape the Rust
// edge decodes: a named map keyed exactly by v/rev/comp/rules/src.
// A drift here (e.g. a renamed/added field) breaks the cross-language
// contract, so we assert the decoded key set explicitly.
func TestIPSRuleBundleBody_MsgpackShape(t *testing.T) {
	t.Parallel()
	body, err := sampleClaims().EncodeBody()
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	var generic map[string]any
	if err := msgpack.Unmarshal(body, &generic); err != nil {
		t.Fatalf("decode as map: %v", err)
	}
	want := []string{"v", "rev", "comp", "rules", "src"}
	if len(generic) != len(want) {
		t.Fatalf("body has %d keys %v, want %d %v", len(generic), keysOf(generic), len(want), want)
	}
	for _, k := range want {
		if _, ok := generic[k]; !ok {
			t.Errorf("body missing key %q (keys: %v)", k, keysOf(generic))
		}
	}
	if v, _ := generic["v"].(uint8); v != IPSRuleSchemaVersion {
		// msgpack may decode small ints as int8/uint8/int64; normalise.
		if iv, ok := asUint64(generic["v"]); !ok || iv != IPSRuleSchemaVersion {
			t.Errorf("schema version = %v, want %d", generic["v"], IPSRuleSchemaVersion)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func asUint64(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint8:
		return uint64(n), true
	case uint64:
		return n, true
	case int8:
		return uint64(n), true
	case int64:
		return uint64(n), true
	case int:
		return uint64(n), true
	default:
		return 0, false
	}
}

// TestIPSSigningKeyID matches the edge's 8-byte-prefix-hex derivation.
func TestIPSSigningKeyID(t *testing.T) {
	t.Parallel()
	pub := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	for i := range pub {
		pub[i] = byte(i)
	}
	got := IPSSigningKeyID(pub)
	if got != "0001020304050607" {
		t.Fatalf("IPSSigningKeyID = %q, want 0001020304050607", got)
	}
	if !strings.HasPrefix(base64.StdEncoding.EncodeToString(pub), "AAEC") {
		t.Errorf("sanity: unexpected pubkey encoding")
	}
}
