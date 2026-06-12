package threatintel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testBundle() *FeedBundle {
	b := newBundle(42, time.Unix(1700000000, 0))
	b.Reputation = []string{"b.example", "a.example", "a.example"}
	b.Categories["ads"] = []string{"y.ads.example", "x.ads.example"}
	b.Categories["empty"] = nil
	return b
}

func TestCanonicalBytesDeterministicAndNormalized(t *testing.T) {
	b1 := testBundle()
	first, err := b1.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Repeated calls are stable (idempotent normalize).
	second, err := b1.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("CanonicalBytes not idempotent")
	}

	// A differently-ordered but equivalent bundle yields identical bytes.
	b2 := newBundle(42, time.Unix(1700000000, 0))
	b2.Reputation = []string{"a.example", "b.example"}
	b2.Categories["ads"] = []string{"x.ads.example", "y.ads.example"}
	other, err := b2.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, other) {
		t.Fatalf("canonical bytes differ for equivalent bundles:\n%s\n%s", first, other)
	}

	// Empty category dropped, reputation deduped/sorted.
	if _, ok := b1.Categories["empty"]; ok {
		t.Fatal("empty category not dropped")
	}
	if got := b1.Reputation; len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("reputation not sorted/deduped: %v", got)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := testBundle().Sign(signer, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if signed.Algorithm != Algorithm {
		t.Fatalf("alg = %q", signed.Algorithm)
	}
	if signed.KeyID != "key-1" {
		t.Fatalf("key_id = %q", signed.KeyID)
	}

	got, err := signed.DecodeVerified(signer.Public())
	if err != nil {
		t.Fatalf("DecodeVerified: %v", err)
	}
	if got.Serial != 42 || got.SchemaVersion != SchemaVersion {
		t.Fatalf("decoded bundle wrong: %+v", got)
	}
	if len(got.Reputation) != 2 {
		t.Fatalf("reputation = %v", got.Reputation)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	signed, err := testBundle().Sign(signer, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.VerifyWith(other.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch, got %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	signer, _ := GenerateSigner()
	signed, err := testBundle().Sign(signer, "")
	if err != nil {
		t.Fatal(err)
	}

	// Flip the payload to a different (validly-encoded) bundle.
	tampered := newBundle(99, time.Unix(1700000001, 0))
	tampered.Reputation = []string{"attacker.example"}
	payload, err := tampered.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	signed.Payload = base64.StdEncoding.EncodeToString(payload)

	if err := signed.VerifyWith(signer.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch on tamper, got %v", err)
	}
}

func TestNewSignerKeyLengths(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := NewSigner(seed); err != nil {
		t.Fatalf("seed-length key rejected: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := NewSigner(priv); err != nil {
		t.Fatalf("expanded key rejected: %v", err)
	}
	if _, err := NewSigner([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for bad key length")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	signer, _ := GenerateSigner()
	signed, _ := testBundle().Sign(signer, "k")
	data, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded SignedBundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := decoded.DecodeVerified(signer.Public()); err != nil {
		t.Fatalf("round-tripped envelope failed verify: %v", err)
	}
}
