package compliance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

func newEvidenceService(t *testing.T) (*compliance.EvidenceService, *compliance.MemoryObjectStore, *compliance.Signer) {
	t.Helper()
	store := memory.NewStore()
	repo := memory.NewComplianceEvidenceRepository(store)
	objStore := compliance.NewMemoryObjectStore()
	signer, err := compliance.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	svc, err := compliance.NewEvidenceService(repo, objStore, signer, nil)
	if err != nil {
		t.Fatalf("NewEvidenceService: %v", err)
	}
	return svc, objStore, signer
}

func TestSigner_SignVerifyRoundTrip(t *testing.T) {
	signer, err := compliance.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	msg := []byte("evidence-bytes")
	sig := signer.Sign(msg)
	if sig == "" {
		t.Fatal("empty signature")
	}
	if err := compliance.VerifySignature(signer.Public(), msg, sig); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	// Tampered payload must fail.
	if err := compliance.VerifySignature(signer.Public(), []byte("tampered"), sig); !errors.Is(err, compliance.ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch on tamper, got %v", err)
	}
	// Garbage (non-hex) signature must fail closed, not panic.
	if err := compliance.VerifySignature(signer.Public(), msg, "zzzz"); !errors.Is(err, compliance.ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch on bad hex, got %v", err)
	}
}

func TestNewSigner_AcceptsSeedAndExpanded(t *testing.T) {
	seed := bytes.Repeat([]byte{0x01}, 32)
	s1, err := compliance.NewSigner(seed)
	if err != nil {
		t.Fatalf("NewSigner(seed): %v", err)
	}
	// Re-deriving from the same seed must yield the same public key so a
	// configured key is stable across restarts.
	s2, err := compliance.NewSigner(seed)
	if err != nil {
		t.Fatalf("NewSigner(seed) again: %v", err)
	}
	if !s1.Public().Equal(s2.Public()) {
		t.Fatal("same seed produced different public keys")
	}
	if _, err := compliance.NewSigner([]byte("short")); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestBundle_ControlsSortedDeduped(t *testing.T) {
	b := compliance.NewBundle(compliance.CollectionWeekly, time.Now())
	b.Add(compliance.EvidenceArtifact{Control: "CC8.1", Name: "ha", Kind: compliance.ArtifactConfigSnapshot, Data: json.RawMessage(`{}`)})
	b.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "rbac", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{}`)})
	b.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "reviews", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{}`)})
	b.Add(compliance.EvidenceArtifact{Control: "", Name: "manifest", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{}`)})

	got := b.Controls()
	want := []string{"CC6.1", "CC8.1"}
	if len(got) != len(want) {
		t.Fatalf("Controls() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Controls() = %v, want %v", got, want)
		}
	}
}

func TestBundle_CanonicalBytesDeterministic(t *testing.T) {
	mk := func() *compliance.EvidenceBundle {
		id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
		b := &compliance.EvidenceBundle{
			ID:             id,
			CollectionType: compliance.CollectionWeekly,
			CollectedAt:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		}
		b.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "rbac", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{"b":2,"a":1}`)})
		return b
	}
	a, err := mk().CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	bb, err := mk().CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if !bytes.Equal(a, bb) {
		t.Fatalf("CanonicalBytes not deterministic:\n%s\n%s", a, bb)
	}
}

func TestEvidenceService_StoreAndDownload(t *testing.T) {
	svc, objStore, signer := newEvidenceService(t)
	ctx := context.Background()

	b := compliance.NewBundle(compliance.CollectionWeekly, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	b.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "rbac", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{"roles":[]}`)})

	row, err := svc.Store(ctx, b)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if row.Status != compliance.StatusCollected {
		t.Fatalf("status = %q, want %q", row.Status, compliance.StatusCollected)
	}
	if row.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if !strings.Contains(row.S3Key, "type=weekly") || !strings.Contains(row.S3Key, "date=2026-03-01") {
		t.Fatalf("unexpected s3 key: %q", row.S3Key)
	}

	gotRow, body, err := svc.Download(ctx, row.ID)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if gotRow.ID != row.ID {
		t.Fatalf("downloaded row id mismatch")
	}
	if err := compliance.VerifySignature(signer.Public(), body, row.Signature); err != nil {
		t.Fatalf("downloaded bytes fail verification: %v", err)
	}

	// Tamper with the archived object and confirm Download fails closed.
	if err := objStore.Put(ctx, row.S3Key, []byte(`{"tampered":true}`)); err != nil {
		t.Fatalf("tamper Put: %v", err)
	}
	if _, _, err := svc.Download(ctx, row.ID); !errors.Is(err, compliance.ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch after tamper, got %v", err)
	}
}

func TestEvidenceService_ListAndLatestByType(t *testing.T) {
	svc, _, _ := newEvidenceService(t)
	ctx := context.Background()

	older := compliance.NewBundle(compliance.CollectionWeekly, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	older.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "rbac", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{}`)})
	newer := compliance.NewBundle(compliance.CollectionWeekly, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	newer.Add(compliance.EvidenceArtifact{Control: "CC6.1", Name: "rbac", Kind: compliance.ArtifactJSONExport, Data: json.RawMessage(`{}`)})

	if _, err := svc.Store(ctx, older); err != nil {
		t.Fatalf("Store older: %v", err)
	}
	if _, err := svc.Store(ctx, newer); err != nil {
		t.Fatalf("Store newer: %v", err)
	}

	latest, err := svc.LatestByType(ctx, compliance.CollectionWeekly)
	if err != nil {
		t.Fatalf("LatestByType: %v", err)
	}
	if !latest.CollectedAt.Equal(newer.CollectedAt) {
		t.Fatalf("LatestByType returned %v, want %v", latest.CollectedAt, newer.CollectedAt)
	}

	page, err := svc.List(ctx, repository.ComplianceEvidenceFilter{}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("List returned %d items, want 2", len(page.Items))
	}
	// Most-recent-first ordering.
	if !page.Items[0].CollectedAt.Equal(newer.CollectedAt) {
		t.Fatalf("List not ordered most-recent-first: %v", page.Items[0].CollectedAt)
	}
}
