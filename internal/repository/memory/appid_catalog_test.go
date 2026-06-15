package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func sampleEntries() []repository.AppIDCatalogEntry {
	return []repository.AppIDCatalogEntry{
		{
			AppID:        "microsoft.teams",
			Category:     "collaboration",
			SNISuffixes:  []string{"teams.microsoft.com"},
			HostSuffixes: []string{"teams.microsoft.com"},
			JA3:          []string{},
			BytePrefixes: []string{},
			Ports:        []int{443},
			Transport:    "tcp",
			Confidence:   90,
		},
		{
			AppID:        "atlassian.jira",
			Category:     "dev-tools",
			SNISuffixes:  []string{"atlassian.net"},
			HostSuffixes: []string{"atlassian.net"},
			JA3:          []string{},
			BytePrefixes: []string{},
			Ports:        []int{443},
			Transport:    "tcp",
			Confidence:   90,
		},
	}
}

func sampleBundle(serial int64) repository.AppIDCatalogBundle {
	return repository.AppIDCatalogBundle{
		Serial:    serial,
		Algorithm: "ed25519",
		KeyID:     "k1",
		PublicKey: []byte{1, 2, 3},
		Payload:   []byte(`{"schema_version":1}`),
		Signature: []byte{9, 8, 7},
		CreatedAt: time.Unix(serial, 0).UTC(),
	}
}

func TestAppIDCatalog_EmptyIsNotFound(t *testing.T) {
	r := NewAppIDCatalogRepository(nil)
	ctx := context.Background()

	if _, err := r.CurrentVersion(ctx); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("CurrentVersion on empty: want ErrNotFound, got %v", err)
	}
	if _, err := r.CurrentEntries(ctx); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("CurrentEntries on empty: want ErrNotFound, got %v", err)
	}
	if _, err := r.CurrentBundle(ctx); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("CurrentBundle on empty: want ErrNotFound, got %v", err)
	}
	vs, err := r.ListVersions(ctx, 0)
	if err != nil {
		t.Fatalf("ListVersions on empty: %v", err)
	}
	if len(vs) != 0 {
		t.Fatalf("ListVersions on empty: want 0, got %d", len(vs))
	}
}

func TestAppIDCatalog_PublishAndRead(t *testing.T) {
	r := NewAppIDCatalogRepository(nil)
	ctx := context.Background()

	v1 := repository.AppIDCatalogVersion{
		Serial: 1, SchemaVersion: 1, AppCount: 2,
		Checksum: "abc", Note: "seed", CreatedAt: time.Unix(1, 0).UTC(),
	}
	if err := r.PublishVersion(ctx, v1, sampleEntries(), sampleBundle(1)); err != nil {
		t.Fatalf("PublishVersion v1: %v", err)
	}

	got, err := r.CurrentVersion(ctx)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if got.Serial != 1 || got.AppCount != 2 || got.Checksum != "abc" {
		t.Fatalf("CurrentVersion mismatch: %+v", got)
	}

	entries, err := r.CurrentEntries(ctx)
	if err != nil {
		t.Fatalf("CurrentEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("CurrentEntries len: want 2, got %d", len(entries))
	}
	// Sorted by app_id: atlassian.jira before microsoft.teams.
	if entries[0].AppID != "atlassian.jira" || entries[1].AppID != "microsoft.teams" {
		t.Fatalf("CurrentEntries not sorted by app_id: %s, %s", entries[0].AppID, entries[1].AppID)
	}
	if entries[1].Serial != 1 {
		t.Fatalf("entry serial: want 1, got %d", entries[1].Serial)
	}

	b, err := r.CurrentBundle(ctx)
	if err != nil {
		t.Fatalf("CurrentBundle: %v", err)
	}
	if b.Serial != 1 || b.Algorithm != "ed25519" || string(b.Payload) != `{"schema_version":1}` {
		t.Fatalf("CurrentBundle mismatch: %+v", b)
	}
}

func TestAppIDCatalog_MonotonicSerial(t *testing.T) {
	r := NewAppIDCatalogRepository(nil)
	ctx := context.Background()

	mkVersion := func(s int64) repository.AppIDCatalogVersion {
		return repository.AppIDCatalogVersion{Serial: s, SchemaVersion: 1, AppCount: 2, CreatedAt: time.Unix(s, 0).UTC()}
	}

	if err := r.PublishVersion(ctx, mkVersion(5), sampleEntries(), sampleBundle(5)); err != nil {
		t.Fatalf("publish serial 5: %v", err)
	}
	// Duplicate serial rejected.
	if err := r.PublishVersion(ctx, mkVersion(5), sampleEntries(), sampleBundle(5)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("duplicate serial: want ErrConflict, got %v", err)
	}
	// Regressing serial rejected.
	if err := r.PublishVersion(ctx, mkVersion(4), sampleEntries(), sampleBundle(4)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("regressing serial: want ErrConflict, got %v", err)
	}
	// Strictly greater accepted; becomes current.
	if err := r.PublishVersion(ctx, mkVersion(6), sampleEntries(), sampleBundle(6)); err != nil {
		t.Fatalf("publish serial 6: %v", err)
	}
	got, err := r.CurrentVersion(ctx)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if got.Serial != 6 {
		t.Fatalf("current serial: want 6, got %d", got.Serial)
	}

	vs, err := r.ListVersions(ctx, 10)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(vs) != 2 || vs[0].Serial != 6 || vs[1].Serial != 5 {
		t.Fatalf("ListVersions newest-first mismatch: %+v", vs)
	}
}

func TestAppIDCatalog_DefensiveCopy(t *testing.T) {
	r := NewAppIDCatalogRepository(nil)
	ctx := context.Background()

	entries := sampleEntries()
	v1 := repository.AppIDCatalogVersion{Serial: 1, SchemaVersion: 1, AppCount: 2, CreatedAt: time.Unix(1, 0).UTC()}
	if err := r.PublishVersion(ctx, v1, entries, sampleBundle(1)); err != nil {
		t.Fatalf("PublishVersion: %v", err)
	}
	// Mutate the caller's slice after publishing — stored state must
	// not change.
	entries[0].AppID = "MUTATED"
	entries[0].SNISuffixes[0] = "evil.example"

	got, err := r.CurrentEntries(ctx)
	if err != nil {
		t.Fatalf("CurrentEntries: %v", err)
	}
	for _, e := range got {
		if e.AppID == "MUTATED" {
			t.Fatalf("stored entry app_id was mutated through caller slice")
		}
		for _, s := range e.SNISuffixes {
			if s == "evil.example" {
				t.Fatalf("stored entry SNI suffix was mutated through caller slice")
			}
		}
	}
}

func TestAppIDCatalog_ListVersionsLimitClamp(t *testing.T) {
	r := NewAppIDCatalogRepository(nil)
	ctx := context.Background()
	for s := int64(1); s <= 3; s++ {
		v := repository.AppIDCatalogVersion{Serial: s, SchemaVersion: 1, AppCount: 2, CreatedAt: time.Unix(s, 0).UTC()}
		if err := r.PublishVersion(ctx, v, sampleEntries(), sampleBundle(s)); err != nil {
			t.Fatalf("publish serial %d: %v", s, err)
		}
	}
	vs, err := r.ListVersions(ctx, 2)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(vs) != 2 || vs[0].Serial != 3 || vs[1].Serial != 2 {
		t.Fatalf("ListVersions limit=2 mismatch: %+v", vs)
	}
}
