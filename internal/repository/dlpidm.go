package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// IDMFingerprintSet is one persisted protected-document fingerprint
// set for WP4 Indexed Document Matching (IDM). A tenant registers a
// protected document (a contract template, a price book, source code)
// and the control plane stores ONLY its winnowed shingle fingerprints
// — never the raw document bytes. The data plane (crates/sng-dlp::idm)
// loads these fingerprints into an inverted index and flags
// partial/derivative copies of the protected document in inspected
// content above a containment threshold.
//
// Privacy contract: Fingerprints are 64-bit SHA-256-derived shingle
// hashes; the source document is fingerprinted once at upload and
// discarded. SourceBytes records only the size of that source for
// capacity reporting — the bytes themselves are never persisted.
//
// The fingerprints are produced by the SAME winnowing algorithm the
// Rust edge uses (locked by a cross-language golden-vector test), so a
// set uploaded here matches what the edge computes for the same
// document and parameters.
type IDMFingerprintSet struct {
	// ID is the row identity (server-assigned on create).
	ID uuid.UUID
	// TenantID is the owning tenant.
	TenantID uuid.UUID
	// Name is a per-tenant-unique human label for the set.
	Name string
	// Description is optional free text.
	Description string
	// ShingleSize / WindowSize / MaxFingerprints are the
	// fingerprinting parameters the set was built with. They are
	// stored so the edge rebuilds the index with the same parameters
	// that produced Fingerprints.
	ShingleSize     int
	WindowSize      int
	MaxFingerprints int
	// Fingerprints are the winnowed shingle hashes (sorted, unique,
	// capped at MaxFingerprints). Persisted as concatenated 8-byte
	// big-endian values in a BYTEA column, mirroring the existing
	// dlp_fingerprints.hash convention.
	Fingerprints []uint64
	// SourceBytes is the size in bytes of the document that was
	// fingerprinted, kept for capacity reporting only.
	SourceBytes int64
	// CreatedAt / UpdatedAt are server-managed timestamps.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IDMFingerprintSetPatch is a sparse update of an IDM fingerprint
// set's metadata. A nil field leaves the column unchanged. Only
// metadata is patchable; replacing a document's content means
// re-fingerprinting it into a new set (the fingerprints are derived,
// immutable evidence of a specific document version).
type IDMFingerprintSetPatch struct {
	Name        *string
	Description *string
}

// IDMFingerprintSetStats is a cheap aggregate over a tenant's
// fingerprint sets for the IDM status surface. It is computed with a
// single SQL aggregate so the status endpoint never loads the
// fingerprint blobs themselves.
type IDMFingerprintSetStats struct {
	// SetCount is the number of registered fingerprint sets.
	SetCount int
	// TotalFingerprints is the sum of fingerprint counts across all
	// sets (the size of the inverted index the edge would build).
	TotalFingerprints int64
	// TotalSourceBytes is the sum of the registered documents' sizes.
	TotalSourceBytes int64
}

// DLPOCRIDMConfig is a tenant's configuration for the WP4 OCR and IDM
// capabilities. One row exists per tenant; a tenant that never writes
// a config behaves exactly like the edge's compiled-in defaults
// (OcrLimits::default and crates/sng-dlp::idm DEFAULT_*). The bounds
// can only narrow a tenant's limits, never loosen them past the
// platform ceilings the edge enforces.
type DLPOCRIDMConfig struct {
	TenantID uuid.UUID
	// OCREnabled toggles image-text extraction for the tenant.
	OCREnabled bool
	// OCRMaxInputBytes / OCRMaxDimension bound the images the edge
	// will decode (defaults mirror OcrLimits::default: 4 MiB, 4096).
	OCRMaxInputBytes int64
	OCRMaxDimension  int
	// IDMEnabled toggles indexed-document matching for the tenant.
	IDMEnabled bool
	// IDMSimilarityThreshold is the containment threshold above which
	// a match is reported (default 0.8).
	IDMSimilarityThreshold float64
	// IDMShingleSize / IDMWindowSize / IDMMaxFingerprints are the
	// default fingerprinting parameters for newly uploaded sets
	// (defaults mirror crates/sng-dlp::idm: 5, 8, 2048).
	IDMShingleSize     int
	IDMWindowSize      int
	IDMMaxFingerprints int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// DLPIDMRepository is the durability boundary for WP4 OCR/IDM control
// plane state: tenant-scoped protected-document fingerprint sets and a
// per-tenant OCR/IDM configuration row.
//
// All methods are tenant-scoped and rely on the shared repository
// sentinels (ErrNotFound, ErrConflict, ErrInvalidArgument). Stores
// only fingerprints/hashes and metadata, never raw protected-document
// contents.
type DLPIDMRepository interface {
	// CreateFingerprintSet stores a new fingerprint set for the
	// tenant. Returns ErrConflict if (tenant_id, name) already
	// exists, ErrInvalidArgument for a nil tenant.
	CreateFingerprintSet(ctx context.Context, tenantID uuid.UUID, set IDMFingerprintSet) (IDMFingerprintSet, error)
	// GetFingerprintSet returns one set by id, scoped to the tenant.
	// Returns ErrNotFound if absent or owned by another tenant.
	GetFingerprintSet(ctx context.Context, tenantID, id uuid.UUID) (IDMFingerprintSet, error)
	// ListFingerprintSets returns the tenant's sets, newest first,
	// using opaque keyset pagination.
	ListFingerprintSets(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[IDMFingerprintSet], error)
	// UpdateFingerprintSet applies a sparse metadata patch. Returns
	// ErrNotFound if absent, ErrConflict on a name collision.
	UpdateFingerprintSet(ctx context.Context, tenantID, id uuid.UUID, patch IDMFingerprintSetPatch) (IDMFingerprintSet, error)
	// DeleteFingerprintSet removes a set. Returns ErrNotFound if absent.
	DeleteFingerprintSet(ctx context.Context, tenantID, id uuid.UUID) error
	// FingerprintSetStats returns a cheap aggregate over the tenant's
	// sets (no fingerprint blobs loaded).
	FingerprintSetStats(ctx context.Context, tenantID uuid.UUID) (IDMFingerprintSetStats, error)

	// GetConfig returns the tenant's OCR/IDM config. Returns
	// ErrNotFound when the tenant has never written one (the service
	// then falls back to defaults).
	GetConfig(ctx context.Context, tenantID uuid.UUID) (DLPOCRIDMConfig, error)
	// UpsertConfig inserts or updates the tenant's OCR/IDM config row.
	UpsertConfig(ctx context.Context, tenantID uuid.UUID, cfg DLPOCRIDMConfig) (DLPOCRIDMConfig, error)
}
