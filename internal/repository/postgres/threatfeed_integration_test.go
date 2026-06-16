//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestThreatFeed_Integration exercises the managed threat-content
// repository (migrations 076-078) against a real Postgres. The tables
// are platform-global (no tenant_id, no RLS), so every operation runs
// via the system-role transaction; there is no per-tenant isolation to
// assert, only the CRUD / upsert / ordering / pruning contract.
func TestThreatFeed_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	repo := store.NewThreatFeedRepository()

	t.Run("UpsertSources_inserts_then_preserves_created_at", func(t *testing.T) {
		err := repo.UpsertSources(bgCtx(), []repository.ThreatFeedSource{
			{Name: "abuse.ch:feodo", DisplayName: "Feodo", Kind: "ip", URL: "https://x/feodo", Weight: 0.9, Enabled: true, DefaultTTLSeconds: 604800},
			{Name: "openphish", DisplayName: "OpenPhish", Kind: "url", URL: "https://x/op", Weight: 0.7, Enabled: true, DefaultTTLSeconds: 259200},
		})
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}

		got, err := repo.ListSources(bgCtx())
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 2 || got[0].Name != "abuse.ch:feodo" || got[1].Name != "openphish" {
			t.Fatalf("list not ordered by name: %+v", got)
		}
		if got[0].CreatedAt.IsZero() || got[0].UpdatedAt.IsZero() {
			t.Fatal("server timestamps should be set")
		}
		created := got[0].CreatedAt

		time.Sleep(5 * time.Millisecond)
		// Re-upsert with changed curated metadata: created_at preserved,
		// curated fields updated. The seed passes Enabled=false but the
		// flag is operator-owned and PRESERVED on conflict (stays true),
		// so the curated boot re-seed can never silently re-enable a feed
		// an operator turned off.
		if err := repo.UpsertSources(bgCtx(), []repository.ThreatFeedSource{
			{Name: "abuse.ch:feodo", DisplayName: "Feodo v2", Kind: "ip", URL: "https://x/feodo2", Weight: 0.95, Enabled: false, DefaultTTLSeconds: 100},
		}); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		got, _ = repo.ListSources(bgCtx())
		if got[0].DisplayName != "Feodo v2" || got[0].Weight != 0.95 {
			t.Fatalf("curated update not applied: %+v", got[0])
		}
		if !got[0].Enabled {
			t.Fatalf("enabled should be preserved on conflict, not overwritten by seed: %+v", got[0])
		}
		if !got[0].CreatedAt.Equal(created) {
			t.Fatalf("created_at changed on update: %v vs %v", got[0].CreatedAt, created)
		}
		if !got[0].UpdatedAt.After(created) {
			t.Fatalf("updated_at not bumped: %v", got[0].UpdatedAt)
		}

		// A real operator disable (direct UPDATE on the platform table)
		// followed by another curated re-seed must remain disabled: the
		// operator's choice is durable across reboots/re-seeds.
		if _, err := store.Pool().Exec(bgCtx(),
			`UPDATE threat_content_sources SET enabled = false WHERE name = 'abuse.ch:feodo'`); err != nil {
			t.Fatalf("operator disable: %v", err)
		}
		if err := repo.UpsertSources(bgCtx(), []repository.ThreatFeedSource{
			{Name: "abuse.ch:feodo", DisplayName: "Feodo v2", Kind: "ip", URL: "https://x/feodo2", Weight: 0.95, Enabled: true, DefaultTTLSeconds: 100},
		}); err != nil {
			t.Fatalf("re-seed after disable: %v", err)
		}
		got, _ = repo.ListSources(bgCtx())
		if got[0].Enabled {
			t.Fatalf("operator disable not preserved across re-seed: %+v", got[0])
		}
	})

	t.Run("IngestState_upsert_and_null_timestamps", func(t *testing.T) {
		// First write with zero timestamps -> stored as SQL NULL ->
		// read back as zero time.
		if err := repo.SaveIngestState(bgCtx(), repository.ThreatFeedIngestState{
			SourceName: "openphish", IndicatorCount: 0, ConsecutiveFailures: 1, LastError: "boom",
		}); err != nil {
			t.Fatalf("save (empty): %v", err)
		}
		states, err := repo.ListIngestState(bgCtx())
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		var op repository.ThreatFeedIngestState
		for _, s := range states {
			if s.SourceName == "openphish" {
				op = s
			}
		}
		if !op.LastSuccessAt.IsZero() || !op.LastAttemptAt.IsZero() {
			t.Fatalf("zero times should round-trip as zero: %+v", op)
		}
		if op.ConsecutiveFailures != 1 || op.LastError != "boom" {
			t.Fatalf("state mismatch: %+v", op)
		}

		// Upsert the same source with success timestamps + validators.
		now := time.Date(2026, 2, 2, 8, 0, 0, 0, time.UTC)
		if err := repo.SaveIngestState(bgCtx(), repository.ThreatFeedIngestState{
			SourceName: "openphish", LastAttemptAt: now, LastSuccessAt: now,
			IndicatorCount: 42, ConsecutiveFailures: 0, ETag: `"v9"`, LastModified: "Mon, 02 Feb 2026 08:00:00 GMT",
		}); err != nil {
			t.Fatalf("save (success): %v", err)
		}
		states, _ = repo.ListIngestState(bgCtx())
		for _, s := range states {
			if s.SourceName == "openphish" {
				op = s
			}
		}
		if op.IndicatorCount != 42 || op.ETag != `"v9"` || op.ConsecutiveFailures != 0 {
			t.Fatalf("upsert not applied: %+v", op)
		}
		if op.LastSuccessAt.IsZero() {
			t.Fatal("last_success_at should be set after success")
		}
	})

	t.Run("Bundles_save_latest_serial_prune", func(t *testing.T) {
		if _, err := repo.LatestBundle(bgCtx()); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("empty LatestBundle: want ErrNotFound, got %v", err)
		}
		if s, err := repo.LatestSerial(bgCtx()); err != nil || s != 0 {
			t.Fatalf("empty LatestSerial: want 0, got %d err=%v", s, err)
		}

		gen := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)
		for _, serial := range []int64{1000, 3000, 2000} {
			if err := repo.SaveBundle(bgCtx(), repository.ThreatFeedBundle{
				Serial: serial, SchemaVersion: 1, GeneratedAt: gen, KeyID: "k", Algorithm: "ed25519",
				IndicatorCount: serial / 1000, SizeBytes: 10, Digest: "d", CountsByType: map[string]int{"ip": int(serial / 1000)},
				Envelope: []byte(`{"alg":"ed25519"}`),
			}); err != nil {
				t.Fatalf("save %d: %v", serial, err)
			}
		}

		latest, err := repo.LatestBundle(bgCtx())
		if err != nil {
			t.Fatalf("latest: %v", err)
		}
		if latest.Serial != 3000 || latest.CountsByType["ip"] != 3 {
			t.Fatalf("latest = %+v", latest)
		}
		if s, _ := repo.LatestSerial(bgCtx()); s != 3000 {
			t.Fatalf("LatestSerial = %d, want 3000", s)
		}

		firstCreated := latest.CreatedAt

		// Serial collision: re-save 3000 with a new envelope -> last-writer-wins.
		time.Sleep(5 * time.Millisecond)
		if err := repo.SaveBundle(bgCtx(), repository.ThreatFeedBundle{
			Serial: 3000, SchemaVersion: 1, GeneratedAt: gen, KeyID: "k2", Algorithm: "ed25519",
			IndicatorCount: 9, Digest: "d2", Envelope: []byte(`{"alg":"ed25519","v":2}`),
		}); err != nil {
			t.Fatalf("re-save 3000: %v", err)
		}
		latest, _ = repo.LatestBundle(bgCtx())
		if latest.KeyID != "k2" || latest.IndicatorCount != 9 {
			t.Fatalf("collision did not overwrite: %+v", latest)
		}
		// created_at marks first-persisted and is preserved on conflict.
		if !latest.CreatedAt.Equal(firstCreated) {
			t.Fatalf("created_at changed on serial collision: %v vs %v", latest.CreatedAt, firstCreated)
		}

		// Keep only the newest 2 (3000, 2000); 1000 is pruned.
		if err := repo.PruneBundles(bgCtx(), 2); err != nil {
			t.Fatalf("prune: %v", err)
		}
		if s, _ := repo.LatestSerial(bgCtx()); s != 3000 {
			t.Fatalf("latest after prune = %d, want 3000", s)
		}
		// keep<=0 is a no-op.
		if err := repo.PruneBundles(bgCtx(), 0); err != nil {
			t.Fatalf("prune 0: %v", err)
		}
	})
}
