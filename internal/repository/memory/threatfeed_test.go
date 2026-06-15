package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestThreatFeedRepository_SourcesUpsertPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewStore().NewThreatFeedRepository()

	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "feedB", DisplayName: "B", Kind: "ip", Weight: 0.9, Enabled: true},
		{Name: "feedA", DisplayName: "A", Kind: "url", Weight: 0.8, Enabled: true},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.ListSources(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].Name != "feedA" || got[1].Name != "feedB" {
		t.Fatalf("list not ordered by name: %+v", got)
	}
	if got[0].CreatedAt.IsZero() || got[0].UpdatedAt.IsZero() {
		t.Fatal("timestamps should be set")
	}
	firstCreated := got[0].CreatedAt

	// Re-upsert feedA with a changed weight: CreatedAt preserved, UpdatedAt bumped.
	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "feedA", DisplayName: "A2", Kind: "url", Weight: 0.5, Enabled: false},
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = repo.ListSources(ctx)
	if got[0].DisplayName != "A2" || got[0].Weight != 0.5 || got[0].Enabled {
		t.Fatalf("update not applied: %+v", got[0])
	}
	if !got[0].CreatedAt.Equal(firstCreated) {
		t.Fatalf("CreatedAt changed on update: %v vs %v", got[0].CreatedAt, firstCreated)
	}
}

func TestThreatFeedRepository_IngestState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewStore().NewThreatFeedRepository()

	if err := repo.SaveIngestState(ctx, repository.ThreatFeedIngestState{
		SourceName: "feedA", ETag: `"v1"`, IndicatorCount: 10,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := repo.SaveIngestState(ctx, repository.ThreatFeedIngestState{
		SourceName: "feedA", ETag: `"v2"`, IndicatorCount: 12, ConsecutiveFailures: 0,
	}); err != nil {
		t.Fatalf("save 2: %v", err)
	}

	got, err := repo.ListIngestState(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ETag != `"v2"` || got[0].IndicatorCount != 12 {
		t.Fatalf("upsert by source_name failed: %+v", got)
	}
	if got[0].UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt should be set")
	}
}

func TestThreatFeedRepository_BundleLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewStore().NewThreatFeedRepository()

	if _, err := repo.LatestBundle(ctx); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("empty LatestBundle: want ErrNotFound, got %v", err)
	}
	if s, err := repo.LatestSerial(ctx); err != nil || s != 0 {
		t.Fatalf("empty LatestSerial: want 0, got %d err=%v", s, err)
	}

	for _, serial := range []int64{100, 200, 150} {
		if err := repo.SaveBundle(ctx, repository.ThreatFeedBundle{
			Serial:       serial,
			Envelope:     []byte("env"),
			CountsByType: map[string]int{"ip": 1},
		}); err != nil {
			t.Fatalf("save %d: %v", serial, err)
		}
	}

	latest, err := repo.LatestBundle(ctx)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Serial != 200 {
		t.Fatalf("LatestBundle serial = %d, want 200", latest.Serial)
	}
	if s, _ := repo.LatestSerial(ctx); s != 200 {
		t.Fatalf("LatestSerial = %d, want 200", s)
	}

	// Mutating the returned bundle must not affect stored state.
	latest.Envelope[0] = 'X'
	latest.CountsByType["ip"] = 999
	again, _ := repo.LatestBundle(ctx)
	if again.Envelope[0] == 'X' || again.CountsByType["ip"] == 999 {
		t.Fatal("stored bundle aliased by returned copy")
	}
}

func TestThreatFeedRepository_PruneKeepsNewest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewStore().NewThreatFeedRepository()
	for _, serial := range []int64{1, 2, 3, 4, 5} {
		if err := repo.SaveBundle(ctx, repository.ThreatFeedBundle{Serial: serial}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	if err := repo.PruneBundles(ctx, 2); err != nil {
		t.Fatalf("prune: %v", err)
	}
	// Only serials 4 and 5 should remain; latest still 5.
	latest, _ := repo.LatestBundle(ctx)
	if latest.Serial != 5 {
		t.Fatalf("latest after prune = %d, want 5", latest.Serial)
	}
	// keep<=0 is a no-op.
	if err := repo.PruneBundles(ctx, 0); err != nil {
		t.Fatalf("prune 0: %v", err)
	}
}

func TestThreatFeedRepository_SharedStatePerStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.NewStore()
	r1 := store.NewThreatFeedRepository()
	r2 := store.NewThreatFeedRepository()

	if err := r1.SaveBundle(ctx, repository.ThreatFeedBundle{Serial: 7}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// A second repository over the SAME store sees the same data.
	latest, err := r2.LatestBundle(ctx)
	if err != nil || latest.Serial != 7 {
		t.Fatalf("repos over same store should share state: %+v err=%v", latest, err)
	}
}
