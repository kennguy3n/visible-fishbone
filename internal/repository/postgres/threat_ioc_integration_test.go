//go:build integration

package postgres_test

import (
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestThreatIOCRepository_Integration exercises the global
// threat_intel_iocs snapshot table against a real Postgres: a
// whole-set ReplaceAll round-trips through LoadAll (including the
// zero-time -> NULL mapping), a second ReplaceAll fully swaps the
// set, and an empty ReplaceAll clears the table.
func TestThreatIOCRepository_Integration(t *testing.T) {
	store, cleanup := startPostgres(t)
	defer cleanup()

	repo := store.NewThreatIOCRepository()
	ctx := bgCtx()

	last := time.Date(2023, 6, 1, 12, 0, 0, 0, time.UTC)
	exp := last.Add(24 * time.Hour)
	first := last.Add(-time.Hour)

	set1 := []repository.ThreatIOC{
		{
			Type: "hash", Value: "44d88612fea8a8f36de82e1278abb02f",
			HashAlgo: "md5", Source: "abuse.ch:malwarebazaar",
			ThreatActor: "APT29", Campaign: "op-x", Confidence: 0.95,
			FirstSeen: first, LastSeen: last, ExpiresAt: exp,
		},
		{
			// Permanent + unknown observation window: all three
			// timestamps zero, must round-trip as NULL -> zero.
			Type: "domain", Value: "evil.example.com",
			Source: "otx", Confidence: 0.6,
		},
	}
	if err := repo.ReplaceAll(ctx, set1); err != nil {
		t.Fatalf("ReplaceAll set1: %v", err)
	}

	got, err := repo.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadAll returned %d rows, want 2", len(got))
	}
	byKey := map[string]repository.ThreatIOC{}
	for _, r := range got {
		byKey[r.Type+"\x00"+r.Value] = r
	}
	h := byKey["hash\x0044d88612fea8a8f36de82e1278abb02f"]
	if h.HashAlgo != "md5" || h.Source != "abuse.ch:malwarebazaar" ||
		h.ThreatActor != "APT29" || h.Campaign != "op-x" || h.Confidence != 0.95 {
		t.Errorf("hash row scalar mismatch: %#v", h)
	}
	if !h.FirstSeen.Equal(first) || !h.LastSeen.Equal(last) || !h.ExpiresAt.Equal(exp) {
		t.Errorf("hash row timestamps mismatch: %#v", h)
	}
	d := byKey["domain\x00evil.example.com"]
	if !d.FirstSeen.IsZero() || !d.LastSeen.IsZero() || !d.ExpiresAt.IsZero() {
		t.Errorf("domain row NULL timestamps did not round-trip to zero: %#v", d)
	}

	// ReplaceAll is a full swap, not an upsert: the old set must be
	// gone and only the new row present.
	set2 := []repository.ThreatIOC{
		{Type: "ip", Value: "203.0.113.10", Source: "feodotracker", Confidence: 0.8},
	}
	if err := repo.ReplaceAll(ctx, set2); err != nil {
		t.Fatalf("ReplaceAll set2: %v", err)
	}
	got, err = repo.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll after swap: %v", err)
	}
	if len(got) != 1 || got[0].Type != "ip" || got[0].Value != "203.0.113.10" {
		t.Fatalf("swap did not replace the set: %#v", got)
	}

	// Empty ReplaceAll clears the table.
	if err := repo.ReplaceAll(ctx, nil); err != nil {
		t.Fatalf("ReplaceAll empty: %v", err)
	}
	got, err = repo.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll after clear: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("clear left %d rows", len(got))
	}
}
