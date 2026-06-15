package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

	// Re-upsert feedA with changed curated metadata: those fields update,
	// CreatedAt is preserved, UpdatedAt is bumped. The Enabled flag is
	// operator-owned, so even though the seed passes Enabled=false here
	// it is PRESERVED at its existing value (true) on conflict.
	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "feedA", DisplayName: "A2", Kind: "url", Weight: 0.5, Enabled: false},
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = repo.ListSources(ctx)
	if got[0].DisplayName != "A2" || got[0].Weight != 0.5 {
		t.Fatalf("curated update not applied: %+v", got[0])
	}
	if !got[0].Enabled {
		t.Fatalf("enabled should be preserved (operator-owned), not overwritten by seed: %+v", got[0])
	}
	if !got[0].CreatedAt.Equal(firstCreated) {
		t.Fatalf("CreatedAt changed on update: %v vs %v", got[0].CreatedAt, firstCreated)
	}
}

func TestThreatFeedRepository_UpsertPreservesOperatorDisable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewStore().NewThreatFeedRepository()

	// An operator-disabled source (inserted with enabled=false).
	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "feedA", DisplayName: "A", Kind: "ip", Weight: 0.9, Enabled: false},
	}); err != nil {
		t.Fatalf("insert disabled: %v", err)
	}

	// The curated boot re-seed upserts it enabled=true; the disable must
	// survive (operator intent wins over the seed default).
	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "feedA", DisplayName: "A", Kind: "ip", Weight: 0.9, Enabled: true},
	}); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	got, _ := repo.ListSources(ctx)
	if len(got) != 1 || got[0].Enabled {
		t.Fatalf("operator disable not preserved across reseed: %+v", got)
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

func TestThreatFeedRepository_BundleSavePreservesCreatedAtOnCollision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.NewStore()
	// An advancing clock: every read returns a strictly later instant, so a
	// re-save that (incorrectly) re-stamped created_at would observe a
	// different value than the original insert.
	base := time.Unix(1_700_000_000, 0).UTC()
	var ticks int64
	store.SetClock(func() time.Time {
		ticks++
		return base.Add(time.Duration(ticks) * time.Second)
	})
	repo := store.NewThreatFeedRepository()

	if err := repo.SaveBundle(ctx, repository.ThreatFeedBundle{
		Serial: 42, KeyID: "k1", IndicatorCount: 5, Envelope: []byte("v1"),
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	first, err := repo.LatestBundle(ctx)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	firstCreated := first.CreatedAt

	// Re-save the same serial with different metadata (a collision). The
	// envelope/metadata is overwritten last-writer-wins, but created_at must
	// reflect the FIRST persist, matching the postgres ON CONFLICT clause.
	if err := repo.SaveBundle(ctx, repository.ThreatFeedBundle{
		Serial: 42, KeyID: "k2", IndicatorCount: 9, Envelope: []byte("v2"),
	}); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	again, err := repo.LatestBundle(ctx)
	if err != nil {
		t.Fatalf("latest 2: %v", err)
	}
	if again.KeyID != "k2" || again.IndicatorCount != 9 {
		t.Fatalf("collision should overwrite metadata: %+v", again)
	}
	if !again.CreatedAt.Equal(firstCreated) {
		t.Fatalf("CreatedAt not preserved on collision: %v vs %v", again.CreatedAt, firstCreated)
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
