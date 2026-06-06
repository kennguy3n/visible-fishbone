package rbi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// stubGuard is a ResidencyGuard whose decision is fixed for the test.
type stubGuard struct{ err error }

func (g stubGuard) Check(context.Context, uuid.UUID) error { return g.err }

func newArtifactSvc(t *testing.T, ap ArtifactPolicy, guard ResidencyGuard) (*Service, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tid := seedTenant(t, store)
	var idCounter uint32
	opts := []Option{
		WithProxy(ProxyConfig{BaseURL: "https://rbi.example.com"}),
		WithSessionTTL(10 * time.Minute),
		WithArtifactRepo(memory.NewRBIArtifactRepository(store)),
		WithArtifactPolicy(ap),
		withClock(func() time.Time { return testClock }),
		withIDGen(func() uuid.UUID {
			idCounter++
			b := []byte{byte(idCounter), byte(idCounter >> 8)}
			return uuid.NewSHA1(uuid.NameSpaceOID, b)
		}),
	}
	if guard != nil {
		opts = append(opts, WithResidencyGuard(guard))
	}
	svc := NewService(memory.NewRBISessionRepository(store), opts...)
	return svc, store, tid
}

func mustSession(t *testing.T, svc *Service, tid uuid.UUID) Session {
	t.Helper()
	sess, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{
		TargetURL: "https://risky.example",
		UserID:    uuid.New(),
	}, nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}

func TestRecordArtifact_AllowedAndPersisted(t *testing.T) {
	svc, _, tid := newArtifactSvc(t, ArtifactPolicy{FileDownload: true}, nil)
	sess := mustSession(t, svc, tid)

	art, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionInbound,
		Filename:  "report.pdf",
		SHA256:    "abc123",
		SizeBytes: 2048,
	}, nil)
	if err != nil {
		t.Fatalf("RecordArtifact: %v", err)
	}
	if art.Kind != ArtifactFileDownload || art.Filename != "report.pdf" {
		t.Fatalf("unexpected artifact: %+v", art)
	}

	got, err := svc.ListArtifacts(context.Background(), tid, sess.ID, 0)
	if err != nil {
		t.Fatalf("ListArtifacts: %v", err)
	}
	if len(got) != 1 || got[0].ID != art.ID {
		t.Fatalf("expected 1 persisted artifact, got %+v", got)
	}
}

func TestRecordArtifact_BlockedByPolicy(t *testing.T) {
	// Default-deny policy: a download is blocked and nothing persists.
	svc, _, tid := newArtifactSvc(t, ArtifactPolicy{}, nil)
	sess := mustSession(t, svc, tid)

	_, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionInbound,
	}, nil)
	if !errors.Is(err, ErrArtifactBlocked) {
		t.Fatalf("expected ErrArtifactBlocked, got %v", err)
	}
	got, _ := svc.ListArtifacts(context.Background(), tid, sess.ID, 0)
	if len(got) != 0 {
		t.Fatalf("blocked artifact must not persist, got %d rows", len(got))
	}
}

func TestRecordArtifact_ResidencyFailClosed(t *testing.T) {
	// Policy permits the transfer, but the residency guard denies the
	// write: the artifact must NOT be persisted.
	svc, _, tid := newArtifactSvc(t, ArtifactPolicy{FileDownload: true},
		stubGuard{err: errors.New("residency: cross-region write rejected")})
	sess := mustSession(t, svc, tid)

	_, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionInbound,
		Filename:  "x.bin",
	}, nil)
	if err == nil {
		t.Fatal("expected residency error, got nil")
	}
	got, _ := svc.ListArtifacts(context.Background(), tid, sess.ID, 0)
	if len(got) != 0 {
		t.Fatalf("residency-rejected artifact must not persist, got %d rows", len(got))
	}
}

func TestRecordArtifact_WrongDirectionBlocked(t *testing.T) {
	svc, _, tid := newArtifactSvc(t, ArtifactPolicy{FileDownload: true, FileUpload: true}, nil)
	sess := mustSession(t, svc, tid)

	// A download declared outbound is malformed and must be rejected.
	_, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionOutbound,
	}, nil)
	if !errors.Is(err, ErrArtifactBlocked) {
		t.Fatalf("expected ErrArtifactBlocked for wrong direction, got %v", err)
	}
}

func TestRecordArtifact_ClosedSessionRejected(t *testing.T) {
	svc, _, tid := newArtifactSvc(t, ArtifactPolicy{FileDownload: true}, nil)
	sess := mustSession(t, svc, tid)
	if err := svc.CloseSession(context.Background(), tid, sess.ID, nil); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	_, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionInbound,
	}, nil)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for closed session, got %v", err)
	}
}

func TestRecordArtifact_TenantIsolation(t *testing.T) {
	svc, store, tid := newArtifactSvc(t, ArtifactPolicy{FileDownload: true}, nil)
	sess := mustSession(t, svc, tid)
	// A different tenant must not be able to record against this session.
	other := seedTenant(t, store)
	_, err := svc.RecordArtifact(context.Background(), other, sess.ID, ArtifactInput{
		Kind:      ArtifactFileDownload,
		Direction: DirectionInbound,
	}, nil)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant session, got %v", err)
	}
}

func TestRecordArtifact_RepoUnavailable(t *testing.T) {
	store := memory.NewStore()
	tid := seedTenant(t, store)
	svc := NewService(memory.NewRBISessionRepository(store),
		WithProxy(ProxyConfig{BaseURL: "https://rbi.example.com"}),
		withClock(func() time.Time { return testClock }),
	)
	sess := mustSession(t, svc, tid)
	_, err := svc.RecordArtifact(context.Background(), tid, sess.ID, ArtifactInput{
		Kind:      ArtifactClipboard,
		Direction: DirectionInbound,
	}, nil)
	if !errors.Is(err, ErrArtifactRepoUnavailable) {
		t.Fatalf("expected ErrArtifactRepoUnavailable, got %v", err)
	}
}
