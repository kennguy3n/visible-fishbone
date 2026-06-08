package memory

import (
	"context"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ThreatIOCRepository is the memory-backed ThreatIOCRepository
// implementation. It mirrors the Postgres driver's whole-set
// snapshot semantics: ReplaceAll swaps the entire slice, LoadAll
// returns a defensive copy. NOT tenant-scoped, matching the global
// threat_intel_iocs table.
type ThreatIOCRepository struct{ s *Store }

// NewThreatIOCRepository binds a Store.
func NewThreatIOCRepository(s *Store) *ThreatIOCRepository {
	return &ThreatIOCRepository{s: s}
}

var _ repository.ThreatIOCRepository = (*ThreatIOCRepository)(nil)

// ReplaceAll atomically swaps the persisted snapshot for the given
// set. A nil/empty slice clears the table.
func (r *ThreatIOCRepository) ReplaceAll(_ context.Context, iocs []repository.ThreatIOC) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if len(iocs) == 0 {
		r.s.threatIOCs = nil
		return nil
	}
	// Copy so a later mutation of the caller's slice cannot bleed
	// into the store (Postgres rows are likewise detached).
	cp := make([]repository.ThreatIOC, len(iocs))
	copy(cp, iocs)
	r.s.threatIOCs = cp
	return nil
}

// LoadAll returns a defensive copy of the persisted snapshot.
func (r *ThreatIOCRepository) LoadAll(_ context.Context) ([]repository.ThreatIOC, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	if len(r.s.threatIOCs) == 0 {
		return nil, nil
	}
	out := make([]repository.ThreatIOC, len(r.s.threatIOCs))
	copy(out, r.s.threatIOCs)
	return out, nil
}
