package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestSimHash_Identical(t *testing.T) {
	content := []byte("the quick brown fox jumps over the lazy dog")
	h1 := SimHash(content)
	h2 := SimHash(content)
	if h1 != h2 {
		t.Errorf("identical content produced different hashes: %x vs %x", h1, h2)
	}
}

func TestSimHash_Similar(t *testing.T) {
	a := []byte("the quick brown fox jumps over the lazy dog")
	b := []byte("the quick brown fox leaps over the lazy dog")
	ha := SimHash(a)
	hb := SimHash(b)
	sim := hammingSimilarity(ha, hb)
	if sim < 0.7 {
		t.Errorf("expected similar hashes (sim >= 0.7), got %f", sim)
	}
}

func TestSimHash_Different(t *testing.T) {
	a := []byte("the quick brown fox jumps over the lazy dog")
	b := []byte("completely unrelated text about quantum physics and entanglement")
	ha := SimHash(a)
	hb := SimHash(b)
	sim := hammingSimilarity(ha, hb)
	if sim > 0.9 {
		t.Errorf("expected different hashes (sim < 0.9), got %f", sim)
	}
}

func TestFingerprintEngine_RegisterAndMatch(t *testing.T) {
	store := memory.NewStore()
	store.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })

	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "test", Tier: repository.TenantTierStarter,
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	fpRepo := memory.NewDLPFingerprintRepository(store)
	eng := NewFingerprintEngine(fpRepo)

	content := []byte("this is a sensitive document about quarterly earnings and revenue projections for fiscal year 2025")
	fp, err := eng.RegisterFingerprint(context.Background(), tenant.ID, "earnings-q1", "text/plain", content)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if fp.ID == uuid.Nil {
		t.Fatal("expected non-nil fingerprint ID")
	}

	// Match identical content.
	matches, err := eng.MatchFingerprints(context.Background(), tenant.ID, content)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Similarity != 1.0 {
		t.Errorf("expected similarity 1.0, got %f", matches[0].Similarity)
	}

	// Non-matching content.
	other := []byte("completely different unrelated text about cooking recipes and kitchen tips")
	noMatches, err := eng.MatchFingerprints(context.Background(), tenant.ID, other)
	if err != nil {
		t.Fatalf("match other: %v", err)
	}
	if len(noMatches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(noMatches))
	}
}
