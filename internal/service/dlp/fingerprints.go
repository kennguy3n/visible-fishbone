package dlp

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ListFingerprints returns paginated fingerprints for the tenant.
func (s *Service) ListFingerprints(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPFingerprint], error) {
	return s.fingerprints.List(ctx, tenantID, page)
}

// RegisterFingerprint registers a document fingerprint for
// near-duplicate detection.
func (s *Service) RegisterFingerprint(ctx context.Context, tenantID uuid.UUID, name, contentType string, content []byte) (repository.DLPFingerprint, error) {
	if name == "" {
		return repository.DLPFingerprint{}, repository.ErrInvalidArgument
	}
	return s.fp.RegisterFingerprint(ctx, tenantID, name, contentType, content)
}

// MatchFingerprints compares content against registered fingerprints.
func (s *Service) MatchFingerprints(ctx context.Context, tenantID uuid.UUID, content []byte) ([]Match, error) {
	fpMatches, err := s.fp.MatchFingerprints(ctx, tenantID, content)
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, fm := range fpMatches {
		out = append(out, Match{
			RuleType:   repository.DLPRuleTypeFingerprint,
			Pattern:    fm.Name,
			Confidence: fm.Similarity,
		})
	}
	return out, nil
}
