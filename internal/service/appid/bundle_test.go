package appid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func sampleBundleApps() []BundleApp {
	return []BundleApp{
		{
			AppID:        "microsoft.teams",
			Category:     "collaboration",
			SNISuffixes:  []string{"teams.microsoft.com", "teams.live.com"},
			HostSuffixes: []string{"teams.microsoft.com"},
			Ports:        []int{443},
			Transport:    "tcp",
			Confidence:   90,
		},
		{
			AppID:        "atlassian.jira",
			Category:     "dev-tools",
			SNISuffixes:  []string{"atlassian.net"},
			HostSuffixes: []string{"atlassian.net"},
			Ports:        []int{443},
			Transport:    "tcp",
			Confidence:   85,
		},
	}
}

func TestCanonicalBytesDeterministicAndSorted(t *testing.T) {
	// Two bundles with the same logical content but different ordering
	// and duplicate entries must canonicalise to identical bytes.
	gen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a := &CatalogBundle{SchemaVersion: SchemaVersion, Serial: 7, GeneratedAt: gen, Apps: sampleBundleApps()}

	shuffled := sampleBundleApps()
	shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
	shuffled[0].SNISuffixes = append([]string{"atlassian.net", "atlassian.net"}, shuffled[0].SNISuffixes...)
	b := &CatalogBundle{SchemaVersion: SchemaVersion, Serial: 7, GeneratedAt: gen, Apps: shuffled}

	ab, err := a.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical a: %v", err)
	}
	bb, err := b.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical b: %v", err)
	}
	if string(ab) != string(bb) {
		t.Fatalf("canonical bytes differ:\n a=%s\n b=%s", ab, bb)
	}

	// app_id ordering is enforced (atlassian before microsoft).
	var parsed CatalogBundle
	if err := json.Unmarshal(ab, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Apps[0].AppID != "atlassian.jira" || parsed.Apps[1].AppID != "microsoft.teams" {
		t.Fatalf("apps not sorted by app_id: %q, %q", parsed.Apps[0].AppID, parsed.Apps[1].AppID)
	}
	// dedup of sni suffixes.
	if len(parsed.Apps[0].SNISuffixes) != 1 {
		t.Fatalf("expected deduped sni, got %v", parsed.Apps[0].SNISuffixes)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	bundle := &CatalogBundle{
		SchemaVersion: SchemaVersion,
		Serial:        42,
		GeneratedAt:   time.Now().UTC(),
		Apps:          sampleBundleApps(),
	}
	env, err := bundle.Sign(signer, "key-1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.Algorithm != Algorithm || env.KeyID != "key-1" {
		t.Fatalf("unexpected envelope header: %+v", env)
	}

	decoded, err := env.DecodeVerified(signer.Public())
	if err != nil {
		t.Fatalf("decode verified: %v", err)
	}
	if decoded.Serial != 42 || len(decoded.Apps) != 2 {
		t.Fatalf("round-trip mismatch: %+v", decoded)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	bundle := &CatalogBundle{SchemaVersion: SchemaVersion, Serial: 1, GeneratedAt: time.Now().UTC(), Apps: sampleBundleApps()}
	env, err := bundle.Sign(signer, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip the payload to a different (validly-encoded) catalog.
	tampered := *bundle
	tampered.Serial = 999
	raw, err := tampered.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(raw)

	if err := env.VerifyWith(signer.Public()); err == nil {
		t.Fatal("expected signature mismatch on tampered payload")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer, _ := GenerateSigner()
	other, _ := GenerateSigner()
	bundle := &CatalogBundle{SchemaVersion: SchemaVersion, Serial: 1, GeneratedAt: time.Now().UTC(), Apps: sampleBundleApps()}
	env, err := bundle.Sign(signer, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := env.VerifyWith(other.Public()); err == nil {
		t.Fatal("expected mismatch when verifying with the wrong key")
	}
	if err := env.VerifyWith(make(ed25519.PublicKey, 3)); err == nil {
		t.Fatal("expected mismatch on malformed key length")
	}
}

func TestNewSignerKeyForms(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	fromExpanded, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("expanded key: %v", err)
	}
	fromSeed, err := NewSigner(priv.Seed())
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if !fromExpanded.Public().Equal(fromSeed.Public()) {
		t.Fatal("seed and expanded forms produced different public keys")
	}
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("expected error on invalid key length")
	}
}
