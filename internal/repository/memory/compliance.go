package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceReportRepository is the memory-backed ComplianceReportRepository.
type ComplianceReportRepository struct{ s *Store }

// NewComplianceReportRepository wires a fresh repo over the shared Store.
func NewComplianceReportRepository(s *Store) *ComplianceReportRepository {
	return &ComplianceReportRepository{s: s}
}

var _ repository.ComplianceReportRepository = (*ComplianceReportRepository)(nil)

func cloneComplianceReport(r repository.ComplianceReport) repository.ComplianceReport {
	out := r
	out.Controls = cloneJSON(r.Controls)
	out.EvidencePack = cloneJSON(r.EvidencePack)
	return out
}

func (r *ComplianceReportRepository) Create(ctx context.Context, tenantID uuid.UUID, report repository.ComplianceReport) (repository.ComplianceReport, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceReport{}, err
	}
	if tenantID == uuid.Nil {
		return repository.ComplianceReport{}, repository.ErrInvalidArgument
	}

	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if report.ID == uuid.Nil {
		report.ID = uuid.New()
	}
	report.TenantID = tenantID
	now := r.s.clock()
	if report.CreatedAt.IsZero() {
		report.CreatedAt = now
	}
	if report.GeneratedAt.IsZero() {
		report.GeneratedAt = now
	}
	if len(report.Controls) == 0 {
		report.Controls = []byte(`[]`)
	}
	if len(report.EvidencePack) == 0 {
		report.EvidencePack = []byte(`{}`)
	}

	report.Controls = cloneJSON(report.Controls)
	report.EvidencePack = cloneJSON(report.EvidencePack)
	r.s.complianceReports[report.ID] = report

	return cloneComplianceReport(report), nil
}

func (r *ComplianceReportRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.ComplianceReport, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceReport{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	report, ok := r.s.complianceReports[id]
	if !ok || report.TenantID != tenantID {
		return repository.ComplianceReport{}, repository.ErrNotFound
	}
	return cloneComplianceReport(report), nil
}

func (r *ComplianceReportRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.ComplianceReport], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.ComplianceReport]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var all []repository.ComplianceReport
	for _, report := range r.s.complianceReports {
		if report.TenantID == tenantID {
			all = append(all, cloneComplianceReport(report))
		}
	}

	sorted := sortByCreatedAtDesc(all,
		func(r repository.ComplianceReport) time.Time { return r.CreatedAt },
		func(r repository.ComplianceReport) uuid.UUID { return r.ID },
		page.Normalize().Order,
	)

	return paginate(sorted, page, func(r repository.ComplianceReport) cursor {
		return cursor{CreatedAt: r.CreatedAt, ID: r.ID}
	}), nil
}
