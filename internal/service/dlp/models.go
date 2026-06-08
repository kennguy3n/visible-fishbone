package dlp

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ErrModelsUnavailable is returned by the model-management methods
// when the service was constructed without a model repository (a nil
// models repo). The classification path stays fully functional; only
// ML model CRUD/assignment is disabled.
var ErrModelsUnavailable = errors.New("dlp: ML model management is not configured")

// ed25519SignatureHexLen is the hex length of an Ed25519 signature
// (64 raw bytes). sng-dlp's `ModelVerifier` decodes exactly this.
const ed25519SignatureHexLen = 128

// sha256HexLen is the hex length of a SHA-256 digest (32 raw bytes).
const sha256HexLen = 64

// ModelInput is the create payload for [Service.RegisterModel]. The
// ONNX artifact itself must already be uploaded to object storage
// under ObjectKey (S3, like cold archives); this call records only
// the metadata plus the digest the signing pipeline and the agent
// verify against.
type ModelInput struct {
	Name          string
	Version       int
	EntityClasses []string
	ObjectKey     string
	SizeBytes     int64
	SHA256        string
}

// RegisterModel validates and records a new model version in the
// draft state. A draft is not assignable until [Service.ValidateModel]
// promotes it (after the Ed25519 signature over the artifact is
// produced by the signing pipeline).
func (s *Service) RegisterModel(ctx context.Context, tenantID uuid.UUID, in ModelInput) (repository.DLPModel, error) {
	if s.models == nil {
		return repository.DLPModel{}, ErrModelsUnavailable
	}
	if err := validateModelInput(in); err != nil {
		return repository.DLPModel{}, err
	}
	return s.models.CreateModel(ctx, tenantID, repository.DLPModel{
		Name:          in.Name,
		Version:       in.Version,
		Status:        repository.DLPModelStatusDraft,
		EntityClasses: in.EntityClasses,
		ObjectKey:     in.ObjectKey,
		SizeBytes:     in.SizeBytes,
		SHA256:        in.SHA256,
	})
}

// ValidateModel promotes a draft model to the validated (assignable)
// state, recording the hex-encoded Ed25519 signature over the ONNX
// bytes. The signature is the trust-chain material the agent's
// `ModelVerifier` checks before hot-swapping the classifier, so a
// malformed signature is rejected here rather than fail-closing the
// model on every device.
func (s *Service) ValidateModel(ctx context.Context, tenantID, id uuid.UUID, signatureHex string) (repository.DLPModel, error) {
	if s.models == nil {
		return repository.DLPModel{}, ErrModelsUnavailable
	}
	if !isHexLen(signatureHex, ed25519SignatureHexLen) {
		return repository.DLPModel{}, fmt.Errorf(
			"%w: model signature must be %d hex chars (Ed25519)",
			repository.ErrInvalidArgument, ed25519SignatureHexLen)
	}
	status := repository.DLPModelStatusValidated
	return s.models.UpdateModel(ctx, tenantID, id, repository.DLPModelPatch{
		Status:    &status,
		Signature: &signatureHex,
	})
}

// RetireModel withdraws a model version. A retired version is not
// assignable; if it is the tenant's active assignment the caller
// must clear the assignment first (DeleteModel enforces the same).
func (s *Service) RetireModel(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPModel, error) {
	if s.models == nil {
		return repository.DLPModel{}, ErrModelsUnavailable
	}
	status := repository.DLPModelStatusRetired
	return s.models.UpdateModel(ctx, tenantID, id, repository.DLPModelPatch{Status: &status})
}

// GetModel returns a single model version.
func (s *Service) GetModel(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPModel, error) {
	if s.models == nil {
		return repository.DLPModel{}, ErrModelsUnavailable
	}
	return s.models.GetModel(ctx, tenantID, id)
}

// ListModels returns paginated model versions for the tenant.
func (s *Service) ListModels(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPModel], error) {
	if s.models == nil {
		return repository.PageResult[repository.DLPModel]{}, ErrModelsUnavailable
	}
	return s.models.ListModels(ctx, tenantID, page)
}

// DeleteModel removes a model version. The repository refuses to
// delete the tenant's active assignment (ErrConflict); clear it
// first via [Service.ClearModelAssignment].
func (s *Service) DeleteModel(ctx context.Context, tenantID, id uuid.UUID) error {
	if s.models == nil {
		return ErrModelsUnavailable
	}
	return s.models.DeleteModel(ctx, tenantID, id)
}

// AssignModel sets the tenant's active model version. Only a
// validated version is assignable; assigning a draft or retired
// version is an invalid-argument error so a half-prepared or
// withdrawn model never reaches an endpoint bundle.
func (s *Service) AssignModel(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPModelAssignment, error) {
	if s.models == nil {
		return repository.DLPModelAssignment{}, ErrModelsUnavailable
	}
	m, err := s.models.GetModel(ctx, tenantID, id)
	if err != nil {
		return repository.DLPModelAssignment{}, err
	}
	if m.Status != repository.DLPModelStatusValidated {
		return repository.DLPModelAssignment{}, fmt.Errorf(
			"%w: only a validated model can be assigned (model %s is %s)",
			repository.ErrInvalidArgument, id, m.Status)
	}
	return s.models.AssignModel(ctx, tenantID, id)
}

// ClearModelAssignment removes the tenant's active assignment,
// falling the endpoint back to regex-only NER on the next bundle.
func (s *Service) ClearModelAssignment(ctx context.Context, tenantID uuid.UUID) error {
	if s.models == nil {
		return ErrModelsUnavailable
	}
	return s.models.ClearAssignment(ctx, tenantID)
}

// AssignedModel returns the tenant's active model version, or
// ErrNotFound if none is assigned.
func (s *Service) AssignedModel(ctx context.Context, tenantID uuid.UUID) (repository.DLPModel, error) {
	if s.models == nil {
		return repository.DLPModel{}, ErrModelsUnavailable
	}
	return s.models.GetAssignedModel(ctx, tenantID)
}

// validateModelInput enforces the structural invariants of a model
// version before it is recorded: a name, a positive version, at
// least one known entity class, a storage key, a positive artifact
// size, and a well-formed SHA-256 digest.
func validateModelInput(in ModelInput) error {
	if in.Name == "" {
		return fmt.Errorf("%w: model name is required", repository.ErrInvalidArgument)
	}
	if in.Version <= 0 {
		return fmt.Errorf("%w: model version must be positive", repository.ErrInvalidArgument)
	}
	if len(in.EntityClasses) == 0 {
		return fmt.Errorf("%w: model must declare at least one entity class", repository.ErrInvalidArgument)
	}
	for _, c := range in.EntityClasses {
		if _, ok := endpointEntityClasses[c]; !ok {
			return fmt.Errorf("%w: unknown entity class %q", repository.ErrInvalidArgument, c)
		}
	}
	if in.ObjectKey == "" {
		return fmt.Errorf("%w: model object key is required", repository.ErrInvalidArgument)
	}
	if in.SizeBytes <= 0 {
		return fmt.Errorf("%w: model size must be positive", repository.ErrInvalidArgument)
	}
	if !isHexLen(in.SHA256, sha256HexLen) {
		return fmt.Errorf("%w: model sha256 must be %d hex chars", repository.ErrInvalidArgument, sha256HexLen)
	}
	return nil
}
