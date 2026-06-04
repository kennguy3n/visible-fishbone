// evidence.go implements the platform-level SOC2 evidence bundle:
// the timestamped, Ed25519-signed collection of control artifacts the
// SOC2 collector produces, the object-store sink that archives the
// bundle bytes under a multi-year compliance-retention policy, and the
// EvidenceService that ties the two together with the
// compliance_evidence index table (migration 039).
//
// Unlike the per-tenant ComplianceReport (report.go), evidence here is
// PLATFORM-level: it attests to the SNG platform's own controls, so
// there is no tenant binding anywhere in this file.
package compliance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Collection types — mirror the compliance_evidence.collection_type
// CHECK constraint in migration 039.
const (
	CollectionWeekly  = "weekly"
	CollectionMonthly = "monthly"
	CollectionManual  = "manual"
)

// Evidence statuses — mirror the compliance_evidence.status CHECK
// constraint in migration 039.
const (
	StatusCollecting = "collecting"
	StatusCollected  = "collected"
	StatusFailed     = "failed"
	StatusAggregated = "aggregated"
)

// DefaultRetentionYears is the SOC2-appropriate object-retention
// window applied to archived evidence bundles. Seven years is the
// common audit-retention floor for SOC2 / financial-adjacent
// programmes.
const DefaultRetentionYears = 7

// ErrSignatureMismatch is returned when a downloaded bundle's bytes do
// not verify against the recorded Ed25519 signature — i.e. the archive
// has been tampered with or corrupted.
var ErrSignatureMismatch = errors.New("compliance: evidence signature mismatch")

// EvidenceArtifact is a single piece of control evidence inside a
// bundle: a JSON export, a config snapshot, or a screenshot reference.
type EvidenceArtifact struct {
	// Control is the SOC2 control this artifact supports (e.g. "CC6.1").
	Control string `json:"control"`
	// Name is a short human label (e.g. "rbac_role_grants").
	Name string `json:"name"`
	// Kind classifies the payload: "json_export", "config_snapshot",
	// or "screenshot".
	Kind string `json:"kind"`
	// Data is the artifact payload. For json_export / config_snapshot
	// it is the exported JSON; for screenshot it is a JSON object with
	// the S3 reference + content hash.
	Data json.RawMessage `json:"data"`
}

// Artifact kinds.
const (
	ArtifactJSONExport     = "json_export"
	ArtifactConfigSnapshot = "config_snapshot"
	ArtifactScreenshot     = "screenshot"
)

// EvidenceBundle is a timestamped, signable collection of control
// artifacts. The zero value is not useful; build bundles via the SOC2
// collector or NewBundle.
type EvidenceBundle struct {
	ID             uuid.UUID          `json:"id"`
	CollectionType string             `json:"collection_type"`
	CollectedAt    time.Time          `json:"collected_at"`
	Artifacts      []EvidenceArtifact `json:"artifacts"`
}

// NewBundle constructs a bundle with a fresh ID and the given
// collection type / timestamp.
func NewBundle(collectionType string, collectedAt time.Time) *EvidenceBundle {
	return &EvidenceBundle{
		ID:             uuid.New(),
		CollectionType: collectionType,
		CollectedAt:    collectedAt.UTC(),
	}
}

// Add appends an artifact to the bundle.
func (b *EvidenceBundle) Add(a EvidenceArtifact) {
	b.Artifacts = append(b.Artifacts, a)
}

// Controls returns the sorted, de-duplicated set of control IDs the
// bundle carries evidence for. Used by gap detection.
func (b *EvidenceBundle) Controls() []string {
	seen := make(map[string]struct{}, len(b.Artifacts))
	out := make([]string, 0, len(b.Artifacts))
	for _, a := range b.Artifacts {
		if a.Control == "" {
			continue
		}
		if _, ok := seen[a.Control]; ok {
			continue
		}
		seen[a.Control] = struct{}{}
		out = append(out, a.Control)
	}
	sort.Strings(out)
	return out
}

// CanonicalBytes returns the deterministic byte encoding of the bundle
// used both as the S3 object body and as the message that is signed.
//
// Determinism matters: the signature is computed over these bytes and
// re-verified on download, so the encoding must be stable across
// processes. encoding/json emits struct fields in declaration order
// and map keys in sorted order, and the artifact slice preserves the
// collector's emission order, so a plain Marshal is canonical here.
func (b *EvidenceBundle) CanonicalBytes() ([]byte, error) {
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence bundle: %w", err)
	}
	return out, nil
}

// Signer signs evidence bundles with an Ed25519 private key. It mirrors
// the policy-bundle signing approach (internal/service/policy): the
// caller owns key custody (config / KMS / Postgres TDE); this type only
// performs the signing operation.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner wraps an Ed25519 private key (64-byte expanded form) or a
// 32-byte seed.
func NewSigner(key []byte) (*Signer, error) {
	switch len(key) {
	case ed25519.SeedSize:
		return &Signer{priv: ed25519.NewKeyFromSeed(key)}, nil
	case ed25519.PrivateKeySize:
		return &Signer{priv: ed25519.PrivateKey(bytes.Clone(key))}, nil
	default:
		return nil, fmt.Errorf("compliance: invalid Ed25519 key length %d (want %d or %d)",
			len(key), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// GenerateSigner creates a Signer backed by a fresh random key. Useful
// for tests and dev; production wires NewSigner from managed key
// material.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("compliance: generate signing key: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the verifying key.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Sign returns the hex-encoded Ed25519 signature over msg.
func (s *Signer) Sign(msg []byte) string {
	return hex.EncodeToString(ed25519.Sign(s.priv, msg))
}

// VerifySignature checks a hex-encoded Ed25519 signature over msg
// against pub. Returns ErrSignatureMismatch on any failure.
func VerifySignature(pub ed25519.PublicKey, msg []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrSignatureMismatch, err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// ObjectStore is the archive sink for evidence bundle bytes. The
// production implementation is S3-backed with object-lock retention;
// tests use an in-memory implementation. Defined as a narrow interface
// so neither the EvidenceService nor its tests depend on the AWS SDK.
type ObjectStore interface {
	// Put writes body at key. Implementations apply the configured
	// compliance retention policy.
	Put(ctx context.Context, key string, body []byte) error
	// Get reads the bytes previously written at key.
	Get(ctx context.Context, key string) ([]byte, error)
}

// EvidenceService persists, signs, archives, and retrieves evidence
// bundles. It is the seam the admin handler and the scheduler depend
// on.
type EvidenceService struct {
	repo   repository.ComplianceEvidenceRepository
	store  ObjectStore
	signer *Signer
	logger *slog.Logger
	now    func() time.Time
	prefix string
}

// EvidenceServiceOption customises an EvidenceService.
type EvidenceServiceOption func(*EvidenceService)

// WithClock overrides the wall-clock (tests).
func WithClock(now func() time.Time) EvidenceServiceOption {
	return func(s *EvidenceService) {
		if now != nil {
			s.now = now
		}
	}
}

// WithKeyPrefix sets the S3 key prefix bundles are stored under.
// Defaults to "compliance-evidence".
func WithKeyPrefix(prefix string) EvidenceServiceOption {
	return func(s *EvidenceService) {
		if prefix != "" {
			s.prefix = prefix
		}
	}
}

// NewEvidenceService constructs an EvidenceService. repo, store and
// signer are required; a nil logger defaults to slog.Default().
func NewEvidenceService(repo repository.ComplianceEvidenceRepository, store ObjectStore, signer *Signer, logger *slog.Logger, opts ...EvidenceServiceOption) (*EvidenceService, error) {
	if repo == nil || store == nil || signer == nil {
		return nil, errors.New("compliance: NewEvidenceService requires repo, store and signer")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &EvidenceService{
		repo:   repo,
		store:  store,
		signer: signer,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		prefix: "compliance-evidence",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// objectKey derives the deterministic S3 key for a bundle:
//
//	{prefix}/type={collection_type}/date={YYYY-MM-DD}/{bundle_id}.json
func (s *EvidenceService) objectKey(b *EvidenceBundle) string {
	return fmt.Sprintf("%s/type=%s/date=%s/%s.json",
		s.prefix, b.CollectionType, b.CollectedAt.UTC().Format("2006-01-02"), b.ID)
}

// Store signs the bundle, archives the canonical bytes to the object
// store, and records an indexed, signed row in compliance_evidence.
//
// The flow is two-phase so a crash mid-upload leaves a 'collecting' row
// for gap detection rather than a silent gap:
//  1. sign + insert row (status=collecting),
//  2. upload bytes,
//  3. transition row to collected (or failed on upload error).
func (s *EvidenceService) Store(ctx context.Context, b *EvidenceBundle) (repository.ComplianceEvidence, error) {
	if b == nil {
		return repository.ComplianceEvidence{}, errors.New("compliance: nil evidence bundle")
	}
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	if b.CollectedAt.IsZero() {
		b.CollectedAt = s.now()
	}

	payload, err := b.CanonicalBytes()
	if err != nil {
		return repository.ComplianceEvidence{}, err
	}
	signature := s.signer.Sign(payload)
	key := s.objectKey(b)

	row, err := s.repo.Create(ctx, repository.ComplianceEvidence{
		ID:             b.ID,
		CollectionType: b.CollectionType,
		CollectedAt:    b.CollectedAt,
		S3Key:          key,
		Signature:      signature,
		Status:         StatusCollecting,
	})
	if err != nil {
		return repository.ComplianceEvidence{}, fmt.Errorf("record evidence row: %w", err)
	}

	if err := s.store.Put(ctx, key, payload); err != nil {
		// Best-effort transition to failed so the gap is visible. The
		// upload error is the one we surface to the caller.
		if _, uerr := s.repo.UpdateStatus(ctx, row.ID, StatusFailed); uerr != nil {
			s.logger.Error("compliance: mark evidence failed",
				slog.String("id", row.ID.String()), slog.Any("error", uerr))
		}
		return repository.ComplianceEvidence{}, fmt.Errorf("archive evidence bundle: %w", err)
	}

	collected, err := s.repo.UpdateStatus(ctx, row.ID, StatusCollected)
	if err != nil {
		return repository.ComplianceEvidence{}, fmt.Errorf("finalise evidence row: %w", err)
	}
	s.logger.Info("compliance: evidence bundle stored",
		slog.String("id", collected.ID.String()),
		slog.String("type", collected.CollectionType),
		slog.String("s3_key", collected.S3Key),
		slog.Int("artifacts", len(b.Artifacts)))
	return collected, nil
}

// List returns evidence rows ordered by collected_at (most recent
// first), optionally filtered.
func (s *EvidenceService) List(ctx context.Context, filter repository.ComplianceEvidenceFilter, page repository.Page) (repository.PageResult[repository.ComplianceEvidence], error) {
	return s.repo.List(ctx, filter, page)
}

// Get returns one evidence row by id.
func (s *EvidenceService) Get(ctx context.Context, id uuid.UUID) (repository.ComplianceEvidence, error) {
	return s.repo.Get(ctx, id)
}

// LatestByType returns the most recent evidence row of the given type
// (or repository.ErrNotFound).
func (s *EvidenceService) LatestByType(ctx context.Context, collectionType string) (repository.ComplianceEvidence, error) {
	return s.repo.LatestByType(ctx, collectionType)
}

// Download fetches the archived bundle bytes for id and verifies them
// against the recorded signature before returning. A signature
// mismatch (tampering / corruption) yields ErrSignatureMismatch.
func (s *EvidenceService) Download(ctx context.Context, id uuid.UUID) (repository.ComplianceEvidence, []byte, error) {
	row, err := s.repo.Get(ctx, id)
	if err != nil {
		return repository.ComplianceEvidence{}, nil, err
	}
	body, err := s.store.Get(ctx, row.S3Key)
	if err != nil {
		return repository.ComplianceEvidence{}, nil, fmt.Errorf("fetch evidence bundle: %w", err)
	}
	if err := VerifySignature(s.signer.Public(), body, row.Signature); err != nil {
		return repository.ComplianceEvidence{}, nil, err
	}
	return row, body, nil
}

// MemoryObjectStore is an in-memory ObjectStore for tests and for the
// dev/test fallback when no S3 bucket is configured. It is safe for
// concurrent use (the scheduler may Put while an admin download Gets),
// guarded by a mutex.
type MemoryObjectStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

// NewMemoryObjectStore returns an empty in-memory store.
func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{objects: map[string][]byte{}}
}

// Put stores a copy of body at key.
func (m *MemoryObjectStore) Put(_ context.Context, key string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = bytes.Clone(body)
	return nil
}

// Get returns a copy of the bytes at key.
func (m *MemoryObjectStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	body, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("compliance: object %q not found", key)
	}
	return bytes.Clone(body), nil
}

// drainBody reads and closes an S3 GetObject body. Kept here so the S3
// store (s3store.go) and any future reader share one helper.
func drainBody(r io.ReadCloser) ([]byte, error) {
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}
