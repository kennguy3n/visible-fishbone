package threatfeed

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// sampleSeen is a fixed observation time for the sample indicators. It
// is deliberately independent of the bundle's generatedAt so the
// content digest (which covers indicator timestamps but NOT the bundle
// envelope's serial/generatedAt) stays stable when only serial and
// generatedAt differ.
var sampleSeen = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

func sampleBundle(serial int64, generatedAt time.Time) *ContentBundle {
	b := newBundle(serial, generatedAt)
	b.Indicators = []Indicator{
		{Type: "ip", Value: "203.0.113.10", Score: 0.9, Sources: []string{"feedB", "feedA", "feedA"}, LastSeen: sampleSeen},
		{Type: "domain", Value: "evil.example", Score: 0.7, Sources: []string{"feedA"}, LastSeen: sampleSeen},
	}
	return b
}

func TestBundle_SignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	gen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	env, err := sampleBundle(1, gen).Sign(signer, "key-1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.Algorithm != Algorithm || env.KeyID != "key-1" {
		t.Fatalf("envelope meta = %+v", env)
	}

	raw, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalSignedBundle(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bundle, err := got.DecodeVerified(signer.Public())
	if err != nil {
		t.Fatalf("decode verified: %v", err)
	}
	if bundle.Serial != 1 || len(bundle.Indicators) != 2 {
		t.Fatalf("round-trip bundle = %+v", bundle)
	}
	// normalize() should have sorted indicators by (type,value): domain first.
	if bundle.Indicators[0].Type != "domain" || bundle.Indicators[1].Type != "ip" {
		t.Fatalf("indicators not normalized/sorted: %+v", bundle.Indicators)
	}
	// Sources sorted + de-duplicated.
	ipSources := bundle.Indicators[1].Sources
	if len(ipSources) != 2 || ipSources[0] != "feedA" || ipSources[1] != "feedB" {
		t.Fatalf("sources not sorted/deduped: %v", ipSources)
	}
}

func TestBundle_TamperedPayloadFails(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	env, _ := sampleBundle(1, time.Now()).Sign(signer, "k")

	// Flip the payload to a different valid bundle's bytes.
	other, _ := newBundleWithOneIndicator().Sign(signer, "k")
	env.Payload = other.Payload // signature no longer matches payload

	if err := env.VerifyWith(signer.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("tampered payload: want ErrSignatureMismatch, got %v", err)
	}
}

func newBundleWithOneIndicator() *ContentBundle {
	b := newBundle(2, time.Now())
	b.Indicators = []Indicator{{Type: "ip", Value: "198.51.100.1", Score: 0.5, Sources: []string{"x"}}}
	return b
}

func TestBundle_TamperedSignatureFails(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	env, _ := sampleBundle(1, time.Now()).Sign(signer, "k")

	sig, _ := base64.StdEncoding.DecodeString(env.Signature)
	sig[0] ^= 0xFF
	env.Signature = base64.StdEncoding.EncodeToString(sig)

	if err := env.VerifyWith(signer.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("tampered signature: want ErrSignatureMismatch, got %v", err)
	}
}

func TestBundle_WrongKeyFails(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	env, _ := sampleBundle(1, time.Now()).Sign(signer, "k")

	if err := env.VerifyWith(other.Public()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("wrong key: want ErrSignatureMismatch, got %v", err)
	}
}

func TestBundle_BadAlgorithmRejected(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	env, _ := sampleBundle(1, time.Now()).Sign(signer, "k")
	env.Algorithm = "rsa"
	err := env.VerifyWith(signer.Public())
	if err == nil || errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("bad algorithm: want a non-mismatch error, got %v", err)
	}
}

func TestBundle_PinnedKeyLengthValidated(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	env, _ := sampleBundle(1, time.Now()).Sign(signer, "k")
	if err := env.VerifyWith(ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("short pinned key should be rejected")
	}
}

func TestBundle_SchemaTooNewRejected(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	b := sampleBundle(1, time.Now())
	b.SchemaVersion = SchemaVersion + 1
	env, _ := b.Sign(signer, "k")
	if _, err := env.DecodeVerified(signer.Public()); err == nil {
		t.Fatal("schema newer than supported should be rejected")
	}
}

func TestBundle_ContentDigestStability(t *testing.T) {
	t.Parallel()
	gen1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	gen2 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Same indicator set, different Serial + GeneratedAt -> identical digest.
	d1 := sampleBundle(1, gen1).ContentDigest()
	d2 := sampleBundle(999, gen2).ContentDigest()
	if d1 != d2 {
		t.Fatalf("digest changed with serial/generatedAt: %s vs %s", d1, d2)
	}

	// The digest covers the indicator SET identity (type/value/hash +
	// contributing sources), NOT the recency-decayed score. A score-only
	// change must reproduce the SAME digest, otherwise the engine would
	// mint and re-publish a new bundle version on every refresh as the
	// recency factor drifts — fleet-wide churn for 5,000 tenants over
	// content that did not actually change.
	scoreOnly := sampleBundle(1, gen1)
	scoreOnly.Indicators[0].Score = 0.0123
	scoreOnly.Indicators[1].Score = 0.999
	if scoreOnly.ContentDigest() != d1 {
		t.Fatal("digest changed after score-only mutation (would defeat churn-avoidance)")
	}

	// Observation timestamps are re-stamped every full re-parse, so a
	// timestamp-only change must likewise leave the digest unchanged.
	timeOnly := sampleBundle(1, gen1)
	timeOnly.Indicators[0].FirstSeen = sampleSeen.Add(-72 * time.Hour)
	timeOnly.Indicators[0].LastSeen = sampleSeen.Add(72 * time.Hour)
	timeOnly.Indicators[0].ExpiresAt = sampleSeen.Add(240 * time.Hour)
	if timeOnly.ContentDigest() != d1 {
		t.Fatal("digest changed after timestamp-only mutation (would defeat churn-avoidance)")
	}

	// A change to the SET identity DOES move the digest: a new value, a
	// change in corroboration (sources), or an added/removed indicator.
	valueChanged := sampleBundle(1, gen1)
	valueChanged.Indicators[0].Value = "203.0.113.99"
	if valueChanged.ContentDigest() == d1 {
		t.Fatal("digest unchanged after indicator value mutation")
	}

	sourcesChanged := sampleBundle(1, gen1)
	sourcesChanged.Indicators[0].Sources = []string{"feedA", "feedB", "feedC"}
	if sourcesChanged.ContentDigest() == d1 {
		t.Fatal("digest unchanged after corroboration (sources) mutation")
	}

	added := sampleBundle(1, gen1)
	added.Indicators = append(added.Indicators, Indicator{
		Type: "domain", Value: "new.example", Sources: []string{"feedA"}, LastSeen: sampleSeen,
	})
	if added.ContentDigest() == d1 {
		t.Fatal("digest unchanged after adding an indicator")
	}
}

func TestBundle_Counts(t *testing.T) {
	t.Parallel()
	total, byType := sampleBundle(1, time.Now()).Counts()
	if total != 2 || byType["ip"] != 1 || byType["domain"] != 1 {
		t.Fatalf("counts total=%d byType=%v", total, byType)
	}
}

func TestNewSigner_KeySizes(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := NewSigner(seed); err != nil {
		t.Fatalf("seed-size key rejected: %v", err)
	}
	expanded := make([]byte, ed25519.PrivateKeySize)
	if _, err := NewSigner(expanded); err != nil {
		t.Fatalf("expanded key rejected: %v", err)
	}
	if _, err := NewSigner([]byte{1, 2, 3}); err == nil {
		t.Fatal("wrong-length key should error")
	}
}

func TestSign_NilSigner(t *testing.T) {
	t.Parallel()
	if _, err := sampleBundle(1, time.Now()).Sign(nil, "k"); err == nil {
		t.Fatal("nil signer should error")
	}
}

func TestSortedUnique(t *testing.T) {
	t.Parallel()
	got := sortedUnique([]string{"b", "", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if !equalStrings(got, want) {
		t.Fatalf("sortedUnique = %v, want %v", got, want)
	}
	if sortedUnique(nil) != nil {
		t.Fatal("sortedUnique(nil) should be nil")
	}
}
