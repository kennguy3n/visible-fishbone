package ai

import (
	"context"
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IOCPersister is the durability seam for the in-memory IOCStore.
// It loads a previously-persisted indicator set on boot and saves
// the active set periodically / on shutdown, so a control-plane
// restart re-warms the store immediately instead of waiting for
// every feed to re-fetch.
//
// It is an interface (rather than a direct repository dependency)
// so the store stays testable with an in-process fake and the
// concrete Postgres mapping lives in one place
// (RepositoryPersister).
type IOCPersister interface {
	// LoadIOCs returns every persisted indicator. The caller
	// (IOCStore.Restore) drops already-expired entries.
	LoadIOCs(ctx context.Context) ([]IOC, error)
	// SaveIOCs replaces the persisted set with the given active
	// indicators (whole-set snapshot semantics).
	SaveIOCs(ctx context.Context, iocs []IOC) error
}

// RepositoryPersister adapts a repository.ThreatIOCRepository to
// the IOCPersister seam, owning the mapping between the rich
// domain ai.IOC and the neutral, primitive-typed repository row.
// Keeping the mapping here (rather than in the data layer) lets
// the repository package stay free of any dependency on the ai
// package and its enums.
type RepositoryPersister struct {
	repo repository.ThreatIOCRepository
}

// NewRepositoryPersister wraps a ThreatIOCRepository.
func NewRepositoryPersister(repo repository.ThreatIOCRepository) *RepositoryPersister {
	return &RepositoryPersister{repo: repo}
}

var _ IOCPersister = (*RepositoryPersister)(nil)

// LoadIOCs reads the persisted rows and maps them back to domain
// indicators.
func (p *RepositoryPersister) LoadIOCs(ctx context.Context) ([]IOC, error) {
	rows, err := p.repo.LoadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("load persisted iocs: %w", err)
	}
	out := make([]IOC, 0, len(rows))
	for _, r := range rows {
		out = append(out, IOC{
			Type:        IOCType(r.Type),
			Value:       r.Value,
			HashAlgo:    HashAlgo(r.HashAlgo),
			Source:      r.Source,
			ThreatActor: r.ThreatActor,
			Campaign:    r.Campaign,
			Confidence:  r.Confidence,
			FirstSeen:   r.FirstSeen,
			LastSeen:    r.LastSeen,
			ExpiresAt:   r.ExpiresAt,
		})
	}
	return out, nil
}

// SaveIOCs maps the active indicators to rows and replaces the
// persisted set.
func (p *RepositoryPersister) SaveIOCs(ctx context.Context, iocs []IOC) error {
	rows := make([]repository.ThreatIOC, 0, len(iocs))
	for _, i := range iocs {
		rows = append(rows, repository.ThreatIOC{
			Type:        string(i.Type),
			Value:       i.Value,
			HashAlgo:    string(i.HashAlgo),
			Source:      i.Source,
			ThreatActor: i.ThreatActor,
			Campaign:    i.Campaign,
			Confidence:  i.Confidence,
			FirstSeen:   i.FirstSeen,
			LastSeen:    i.LastSeen,
			ExpiresAt:   i.ExpiresAt,
		})
	}
	if err := p.repo.ReplaceAll(ctx, rows); err != nil {
		return fmt.Errorf("save iocs: %w", err)
	}
	return nil
}
