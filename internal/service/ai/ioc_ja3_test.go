package ai

import (
	"context"
	"testing"
)

// sampleJA3 is a representative JA3 hash (the 32-char MD5 form
// Suricata's ja3.hash keyword matches).
const sampleJA3 = "e7d705a3286e19ea42f587b344ee6865"

func TestNormalizeJA3(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"canonical", sampleJA3, sampleJA3, true},
		{"uppercase lowered", "E7D705A3286E19EA42F587B344EE6865", sampleJA3, true},
		{"trims space", "  " + sampleJA3 + "\n", sampleJA3, true},
		{"too short", "abcd", "", false},
		{"sha1 length rejected", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "", false},
		{"non hex", "z7d705a3286e19ea42f587b344ee6865", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := normalizeJA3(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("normalizeJA3(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNewIOC_JA3(t *testing.T) {
	t.Parallel()
	ioc, ok := NewIOC(IOCTypeJA3, "E7D705A3286E19EA42F587B344EE6865", IOCMeta{Source: "otx", Confidence: 0.9})
	if !ok {
		t.Fatal("NewIOC(JA3) rejected a valid fingerprint")
	}
	if ioc.Type != IOCTypeJA3 || ioc.Value != sampleJA3 {
		t.Fatalf("got type=%q value=%q", ioc.Type, ioc.Value)
	}
	if ioc.Key() != "ja3\x00"+sampleJA3 {
		t.Fatalf("Key() = %q", ioc.Key())
	}
	if !IOCTypeJA3.Valid() {
		t.Fatal("IOCTypeJA3 should be Valid()")
	}
	if _, ok := NewIOC(IOCTypeJA3, "not-a-hash", IOCMeta{}); ok {
		t.Fatal("NewIOC(JA3) accepted a malformed value")
	}
}

func TestIOCStore_JA3_CountsSnapshotPersist(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	ja3, _ := NewIOC(IOCTypeJA3, sampleJA3, IOCMeta{Source: "otx", Confidence: 0.9})
	dom, _ := NewIOC(IOCTypeDomain, "evil.example", IOCMeta{Source: "otx", Confidence: 0.9})
	store.Upsert(ja3, dom)

	if c := store.SizeByType(); c.JA3s != 1 || c.Domains != 1 || c.Total != 2 {
		t.Fatalf("SizeByType = %+v", c)
	}
	if c := store.SizeBySource()["otx"]; c.JA3s != 1 {
		t.Fatalf("SizeBySource[otx].JA3s = %d, want 1", c.JA3s)
	}
	snap := store.Snapshot()
	if len(snap.JA3s) != 1 || snap.JA3s[0].Value != sampleJA3 {
		t.Fatalf("Snapshot.JA3s = %+v", snap.JA3s)
	}

	// candidateKeys must probe the ja3 key so a live query of the
	// fingerprint matches the stored JA3 IOC.
	matches, err := store.QueryIOCs(context.Background(), []string{sampleJA3})
	if err != nil {
		t.Fatalf("QueryIOCs: %v", err)
	}
	var sawJA3 bool
	for _, m := range matches {
		if m.ThreatType == string(IOCTypeJA3) {
			sawJA3 = true
		}
	}
	if !sawJA3 {
		t.Fatalf("QueryIOCs(%q) did not match the stored JA3 IOC: %+v", sampleJA3, matches)
	}

	// Round-trip through an in-memory persister.
	p := &memPersister{}
	if _, err := store.Persist(context.Background(), p); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	restored := NewIOCStore()
	if _, err := restored.Restore(context.Background(), p); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	assertSameSnapshot(t, store.Snapshot(), restored.Snapshot())
}

// memPersister is a trivial in-memory IOCPersister for round-trip
// tests. It is defined here (rather than reused) to keep this test
// file self-contained.
type memPersister struct{ iocs []IOC }

func (m *memPersister) SaveIOCs(_ context.Context, iocs []IOC) error {
	m.iocs = append([]IOC(nil), iocs...)
	return nil
}

func (m *memPersister) LoadIOCs(_ context.Context) ([]IOC, error) {
	return append([]IOC(nil), m.iocs...), nil
}

var _ IOCPersister = (*memPersister)(nil)
