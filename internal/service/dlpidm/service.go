package dlpidm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// OCR configuration defaults. These mirror the data-plane OcrLimits
// defaults and the migration column defaults exactly.
const (
	// DefaultOCRMaxInputBytes bounds a single image OCR input (4 MiB).
	DefaultOCRMaxInputBytes = 4 << 20
	// DefaultOCRMaxDimension bounds an image's width/height in pixels.
	DefaultOCRMaxDimension = 4096
)

// Validation bounds. These match the CHECK constraints in migrations
// 086/087 so the service returns a clean ErrInvalidArgument instead of
// relying on a database round-trip to reject bad input.
const (
	maxNameLen        = 200
	maxDescriptionLen = 2000

	minShingleSize, maxShingleSizeBound         = 1, 64
	minWindowSize, maxWindowSizeBound           = 1, 256
	minMaxFingerprints, maxMaxFingerprintsBound = 1, 65536
	minOCRMaxInputBytes, maxOCRMaxInputBytes    = 1024, 16 << 20
	minOCRMaxDimension, maxOCRMaxDimension      = 16, 8192
)

// Service manages per-tenant protected-document fingerprint sets and
// the OCR/IDM configuration. It computes fingerprints in Go using the
// parity-locked algorithm in fingerprint.go and persists only the
// resulting hashes — never the raw protected document.
type Service struct {
	repo   repository.DLPIDMRepository
	logger *slog.Logger
}

// New returns a ready-to-use dlpidm service.
func New(repo repository.DLPIDMRepository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{repo: repo, logger: logger}
}

// RegisterDocumentInput is the request to fingerprint and register a
// protected document. Content is the raw document text; it is
// fingerprinted once and never stored. The optional parameter pointers
// override the tenant's effective configuration for this set only.
type RegisterDocumentInput struct {
	Name            string
	Description     string
	Content         string
	ShingleSize     *int
	WindowSize      *int
	MaxFingerprints *int
}

// ConfigInput is a full replacement of a tenant's OCR/IDM config.
type ConfigInput struct {
	OCREnabled             bool
	OCRMaxInputBytes       int64
	OCRMaxDimension        int
	IDMEnabled             bool
	IDMSimilarityThreshold float64
	IDMShingleSize         int
	IDMWindowSize          int
	IDMMaxFingerprints     int
}

// Status combines a tenant's effective config with aggregate
// fingerprint-set statistics, backing the read-only status endpoint.
type Status struct {
	Config repository.DLPOCRIDMConfig
	Stats  repository.IDMFingerprintSetStats
}

// DefaultConfig returns the compiled-in no-ops configuration used when
// a tenant has never customized its settings. It mirrors the migration
// column defaults and the data-plane defaults.
func DefaultConfig(tenantID uuid.UUID) repository.DLPOCRIDMConfig {
	return repository.DLPOCRIDMConfig{
		TenantID:               tenantID,
		OCREnabled:             true,
		OCRMaxInputBytes:       DefaultOCRMaxInputBytes,
		OCRMaxDimension:        DefaultOCRMaxDimension,
		IDMEnabled:             true,
		IDMSimilarityThreshold: DefaultSimilarityThreshold,
		IDMShingleSize:         DefaultShingleSize,
		IDMWindowSize:          DefaultWindowSize,
		IDMMaxFingerprints:     DefaultMaxFingerprints,
	}
}

// RegisterDocument fingerprints a protected document and persists only
// its fingerprint set. The raw content never leaves this function.
func (svc *Service) RegisterDocument(
	ctx context.Context,
	tenantID uuid.UUID,
	in RegisterDocumentInput,
) (repository.IDMFingerprintSet, error) {
	var zero repository.IDMFingerprintSet

	name := strings.TrimSpace(in.Name)
	if name == "" {
		return zero, fmt.Errorf("%w: name is required", repository.ErrInvalidArgument)
	}
	if len(name) > maxNameLen {
		return zero, fmt.Errorf("%w: name exceeds %d characters", repository.ErrInvalidArgument, maxNameLen)
	}
	if len(in.Description) > maxDescriptionLen {
		return zero, fmt.Errorf("%w: description exceeds %d characters", repository.ErrInvalidArgument, maxDescriptionLen)
	}

	cfg, err := svc.effectiveConfig(ctx, tenantID)
	if err != nil {
		return zero, err
	}

	params := FingerprintParams{
		ShingleSize:     cfg.IDMShingleSize,
		Window:          cfg.IDMWindowSize,
		MaxFingerprints: cfg.IDMMaxFingerprints,
		MaxScanBytes:    DefaultMaxScanBytes,
	}
	if in.ShingleSize != nil {
		params.ShingleSize = *in.ShingleSize
	}
	if in.WindowSize != nil {
		params.Window = *in.WindowSize
	}
	if in.MaxFingerprints != nil {
		params.MaxFingerprints = *in.MaxFingerprints
	}
	if err := validateParams(params); err != nil {
		return zero, err
	}

	fingerprints := FingerprintDocument(in.Content, params)
	if len(fingerprints) == 0 {
		return zero, fmt.Errorf(
			"%w: document produced no fingerprints (content too short or empty)",
			repository.ErrInvalidArgument,
		)
	}

	set := repository.IDMFingerprintSet{
		TenantID:        tenantID,
		Name:            name,
		Description:     in.Description,
		ShingleSize:     params.ShingleSize,
		WindowSize:      params.Window,
		MaxFingerprints: params.MaxFingerprints,
		Fingerprints:    fingerprints,
		SourceBytes:     int64(len(in.Content)),
	}
	return svc.repo.CreateFingerprintSet(ctx, tenantID, set)
}

// GetSet returns one fingerprint set by id.
func (svc *Service) GetSet(ctx context.Context, tenantID, id uuid.UUID) (repository.IDMFingerprintSet, error) {
	return svc.repo.GetFingerprintSet(ctx, tenantID, id)
}

// ListSets returns a page of the tenant's fingerprint sets.
func (svc *Service) ListSets(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IDMFingerprintSet], error) {
	return svc.repo.ListFingerprintSets(ctx, tenantID, page)
}

// UpdateSet patches a fingerprint set's mutable metadata (name and
// description). Fingerprints are immutable derived evidence: replacing
// the protected document means registering a new set.
func (svc *Service) UpdateSet(
	ctx context.Context,
	tenantID, id uuid.UUID,
	patch repository.IDMFingerprintSetPatch,
) (repository.IDMFingerprintSet, error) {
	var zero repository.IDMFingerprintSet
	if patch.Name == nil && patch.Description == nil {
		return zero, fmt.Errorf("%w: no fields to update", repository.ErrInvalidArgument)
	}
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return zero, fmt.Errorf("%w: name is required", repository.ErrInvalidArgument)
		}
		if len(name) > maxNameLen {
			return zero, fmt.Errorf("%w: name exceeds %d characters", repository.ErrInvalidArgument, maxNameLen)
		}
		patch.Name = &name
	}
	if patch.Description != nil && len(*patch.Description) > maxDescriptionLen {
		return zero, fmt.Errorf("%w: description exceeds %d characters", repository.ErrInvalidArgument, maxDescriptionLen)
	}
	return svc.repo.UpdateFingerprintSet(ctx, tenantID, id, patch)
}

// DeleteSet removes a fingerprint set.
func (svc *Service) DeleteSet(ctx context.Context, tenantID, id uuid.UUID) error {
	return svc.repo.DeleteFingerprintSet(ctx, tenantID, id)
}

// GetConfig returns the tenant's effective OCR/IDM config, filling
// compiled-in defaults when the tenant has never customized it.
func (svc *Service) GetConfig(ctx context.Context, tenantID uuid.UUID) (repository.DLPOCRIDMConfig, error) {
	return svc.effectiveConfig(ctx, tenantID)
}

// PutConfig validates and upserts a tenant's OCR/IDM config.
func (svc *Service) PutConfig(
	ctx context.Context,
	tenantID uuid.UUID,
	in ConfigInput,
) (repository.DLPOCRIDMConfig, error) {
	var zero repository.DLPOCRIDMConfig
	if err := validateConfig(in); err != nil {
		return zero, err
	}
	cfg := repository.DLPOCRIDMConfig{
		TenantID:               tenantID,
		OCREnabled:             in.OCREnabled,
		OCRMaxInputBytes:       in.OCRMaxInputBytes,
		OCRMaxDimension:        in.OCRMaxDimension,
		IDMEnabled:             in.IDMEnabled,
		IDMSimilarityThreshold: in.IDMSimilarityThreshold,
		IDMShingleSize:         in.IDMShingleSize,
		IDMWindowSize:          in.IDMWindowSize,
		IDMMaxFingerprints:     in.IDMMaxFingerprints,
	}
	return svc.repo.UpsertConfig(ctx, tenantID, cfg)
}

// Status returns the tenant's effective config plus aggregate
// fingerprint-set statistics.
func (svc *Service) Status(ctx context.Context, tenantID uuid.UUID) (Status, error) {
	cfg, err := svc.effectiveConfig(ctx, tenantID)
	if err != nil {
		return Status{}, err
	}
	stats, err := svc.repo.FingerprintSetStats(ctx, tenantID)
	if err != nil {
		return Status{}, err
	}
	return Status{Config: cfg, Stats: stats}, nil
}

// effectiveConfig returns the stored config or the compiled-in default
// when none exists.
func (svc *Service) effectiveConfig(ctx context.Context, tenantID uuid.UUID) (repository.DLPOCRIDMConfig, error) {
	cfg, err := svc.repo.GetConfig(ctx, tenantID)
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, repository.ErrNotFound) {
		return DefaultConfig(tenantID), nil
	}
	return repository.DLPOCRIDMConfig{}, err
}

// validateParams enforces the fingerprint-parameter bounds.
func validateParams(p FingerprintParams) error {
	if p.ShingleSize < minShingleSize || p.ShingleSize > maxShingleSizeBound {
		return fmt.Errorf("%w: shingle_size must be between %d and %d", repository.ErrInvalidArgument, minShingleSize, maxShingleSizeBound)
	}
	if p.Window < minWindowSize || p.Window > maxWindowSizeBound {
		return fmt.Errorf("%w: window_size must be between %d and %d", repository.ErrInvalidArgument, minWindowSize, maxWindowSizeBound)
	}
	if p.MaxFingerprints < minMaxFingerprints || p.MaxFingerprints > maxMaxFingerprintsBound {
		return fmt.Errorf("%w: max_fingerprints must be between %d and %d", repository.ErrInvalidArgument, minMaxFingerprints, maxMaxFingerprintsBound)
	}
	return nil
}

// validateConfig enforces the OCR/IDM config bounds.
func validateConfig(in ConfigInput) error {
	if in.OCRMaxInputBytes < minOCRMaxInputBytes || in.OCRMaxInputBytes > maxOCRMaxInputBytes {
		return fmt.Errorf("%w: ocr_max_input_bytes must be between %d and %d", repository.ErrInvalidArgument, minOCRMaxInputBytes, maxOCRMaxInputBytes)
	}
	if in.OCRMaxDimension < minOCRMaxDimension || in.OCRMaxDimension > maxOCRMaxDimension {
		return fmt.Errorf("%w: ocr_max_dimension must be between %d and %d", repository.ErrInvalidArgument, minOCRMaxDimension, maxOCRMaxDimension)
	}
	if !(in.IDMSimilarityThreshold > 0 && in.IDMSimilarityThreshold <= 1) {
		return fmt.Errorf("%w: idm_similarity_threshold must be in (0, 1]", repository.ErrInvalidArgument)
	}
	if in.IDMShingleSize < minShingleSize || in.IDMShingleSize > maxShingleSizeBound {
		return fmt.Errorf("%w: idm_shingle_size must be between %d and %d", repository.ErrInvalidArgument, minShingleSize, maxShingleSizeBound)
	}
	if in.IDMWindowSize < minWindowSize || in.IDMWindowSize > maxWindowSizeBound {
		return fmt.Errorf("%w: idm_window_size must be between %d and %d", repository.ErrInvalidArgument, minWindowSize, maxWindowSizeBound)
	}
	if in.IDMMaxFingerprints < minMaxFingerprints || in.IDMMaxFingerprints > maxMaxFingerprintsBound {
		return fmt.Errorf("%w: idm_max_fingerprints must be between %d and %d", repository.ErrInvalidArgument, minMaxFingerprints, maxMaxFingerprintsBound)
	}
	return nil
}
