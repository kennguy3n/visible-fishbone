package policy

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SD-WAN SLA template management.
//
// An SLA template is a per-tenant, named set of path-quality
// thresholds (latency / loss / jitter / throughput) that the SD-WAN
// enforcement plane (the `sng-sdwan` crate) evaluates probe results
// against to raise sustained-breach violations and drive automatic
// failover. The control plane lets operators CRUD these templates and
// compiles the active set into the SD-WAN slice of the policy bundle.
//
// The wire contract chosen here (see [SLABundleEntry]) is an explicit,
// self-describing JSON object per SLA class rather than a direct
// re-serialisation of the Rust `SlaPolicySet`: the Rust type's serde
// shape is an internal detail of the enforcement plane, whereas the
// bundle slice is a stable cross-language contract. The class strings
// match `crate::sla::SlaClass::as_str` ("business-critical",
// "real-time", "best-effort").

// SLA class wire identifiers. These match the Rust
// `SlaClass::as_str` values and are the values persisted in the
// `sdwan_sla_policies.traffic_class` column.
const (
	// SLAClassBusinessCritical is the tightest SLA — low latency
	// and near-zero loss (maps from `inspect_full` apps).
	SLAClassBusinessCritical = "business-critical"
	// SLAClassRealTime is latency/jitter-sensitive media (maps
	// from `trusted_media_bypass` apps).
	SLAClassRealTime = "real-time"
	// SLAClassBestEffort carries no SLA enforcement.
	SLAClassBestEffort = "best-effort"
)

// SLADefaultConsecutiveBreaches is the number of consecutive probe
// intervals a metric must breach before a violation is raised. It
// mirrors the Rust `default_consecutive_breaches` so a compiled
// bundle that omits the field and one that carries this value behave
// identically.
const SLADefaultConsecutiveBreaches uint32 = 3

// validSLAClass reports whether s is a recognised SLA class.
func validSLAClass(s string) bool {
	switch s {
	case SLAClassBusinessCritical, SLAClassRealTime, SLAClassBestEffort:
		return true
	default:
		return false
	}
}

// SLATemplate is a persisted per-tenant SLA policy template. It maps
// one-to-one onto a row of the `sdwan_sla_policies` table.
type SLATemplate struct {
	ID                uuid.UUID `json:"id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	Name              string    `json:"name"`
	TrafficClass      string    `json:"traffic_class"`
	MaxLatencyMs      *float64  `json:"max_latency_ms,omitempty"`
	MaxLossPct        *float64  `json:"max_loss_pct,omitempty"`
	MaxJitterMs       *float64  `json:"max_jitter_ms,omitempty"`
	MinThroughputMbps *float64  `json:"min_throughput_mbps,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// SLATemplateInput is the mutable payload for creating or updating a
// template. Identity and timestamps are owned by the service.
type SLATemplateInput struct {
	Name              string
	TrafficClass      string
	MaxLatencyMs      *float64
	MaxLossPct        *float64
	MaxJitterMs       *float64
	MinThroughputMbps *float64
}

// Validate enforces the value domain. Returns an error wrapping
// [repository.ErrInvalidArgument] so the HTTP boundary can map it to
// a 400.
func (in SLATemplateInput) Validate() error {
	if in.Name == "" {
		return fmt.Errorf("%w: sla template name must not be empty", repository.ErrInvalidArgument)
	}
	if !validSLAClass(in.TrafficClass) {
		return fmt.Errorf(
			"%w: sla template traffic_class %q is not a recognised SLA class",
			repository.ErrInvalidArgument, in.TrafficClass,
		)
	}
	if err := validateThreshold("max_latency_ms", in.MaxLatencyMs, math.MaxFloat32); err != nil {
		return err
	}
	if err := validateThreshold("max_loss_pct", in.MaxLossPct, 100); err != nil {
		return err
	}
	if err := validateThreshold("max_jitter_ms", in.MaxJitterMs, math.MaxFloat32); err != nil {
		return err
	}
	if err := validateThreshold("min_throughput_mbps", in.MinThroughputMbps, math.MaxFloat32); err != nil {
		return err
	}
	return nil
}

// validateThreshold rejects non-finite, negative, or above-limit
// threshold values. A nil pointer (metric not gating) is always
// valid.
func validateThreshold(field string, v *float64, upper float64) error {
	if v == nil {
		return nil
	}
	if math.IsNaN(*v) || math.IsInf(*v, 0) {
		return fmt.Errorf("%w: sla %s must be finite", repository.ErrInvalidArgument, field)
	}
	if *v < 0 {
		return fmt.Errorf("%w: sla %s must be >= 0", repository.ErrInvalidArgument, field)
	}
	if *v > upper {
		return fmt.Errorf("%w: sla %s must be <= %g", repository.ErrInvalidArgument, field, upper)
	}
	return nil
}

// SLATemplateRepository persists [SLATemplate] rows. Implementations
// enforce tenant scoping and the unique (tenant_id, name) constraint
// (returning [repository.ErrConflict] on collision and
// [repository.ErrNotFound] for a missing row).
type SLATemplateRepository interface {
	Create(ctx context.Context, tmpl SLATemplate) (SLATemplate, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (SLATemplate, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]SLATemplate, error)
	Update(ctx context.Context, tmpl SLATemplate) (SLATemplate, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// SLATemplateService is the CRUD + compile surface for per-tenant
// SD-WAN SLA templates.
type SLATemplateService struct {
	repo SLATemplateRepository
	now  func() time.Time
}

// SLATemplateOption configures an [SLATemplateService].
type SLATemplateOption func(*SLATemplateService)

// WithSLAClock overrides the wall clock (for deterministic tests).
func WithSLAClock(now func() time.Time) SLATemplateOption {
	return func(s *SLATemplateService) {
		if now != nil {
			s.now = now
		}
	}
}

// NewSLATemplateService constructs a service over the given
// repository.
func NewSLATemplateService(repo SLATemplateRepository, opts ...SLATemplateOption) *SLATemplateService {
	s := &SLATemplateService{
		repo: repo,
		now:  time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Create validates the input and persists a new template.
func (s *SLATemplateService) Create(ctx context.Context, tenantID uuid.UUID, in SLATemplateInput) (SLATemplate, error) {
	if err := in.Validate(); err != nil {
		return SLATemplate{}, err
	}
	now := s.now().UTC()
	tmpl := SLATemplate{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Name:              in.Name,
		TrafficClass:      in.TrafficClass,
		MaxLatencyMs:      in.MaxLatencyMs,
		MaxLossPct:        in.MaxLossPct,
		MaxJitterMs:       in.MaxJitterMs,
		MinThroughputMbps: in.MinThroughputMbps,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	return s.repo.Create(ctx, tmpl)
}

// Get returns a single template by id, scoped to the tenant.
func (s *SLATemplateService) Get(ctx context.Context, tenantID, id uuid.UUID) (SLATemplate, error) {
	return s.repo.Get(ctx, tenantID, id)
}

// List returns the tenant's templates ordered by name.
func (s *SLATemplateService) List(ctx context.Context, tenantID uuid.UUID) ([]SLATemplate, error) {
	templates, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})
	return templates, nil
}

// Update validates the input and replaces the mutable fields of an
// existing template, preserving its identity and creation time.
func (s *SLATemplateService) Update(ctx context.Context, tenantID, id uuid.UUID, in SLATemplateInput) (SLATemplate, error) {
	if err := in.Validate(); err != nil {
		return SLATemplate{}, err
	}
	existing, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return SLATemplate{}, err
	}
	existing.Name = in.Name
	existing.TrafficClass = in.TrafficClass
	existing.MaxLatencyMs = in.MaxLatencyMs
	existing.MaxLossPct = in.MaxLossPct
	existing.MaxJitterMs = in.MaxJitterMs
	existing.MinThroughputMbps = in.MinThroughputMbps
	existing.UpdatedAt = s.now().UTC()
	return s.repo.Update(ctx, existing)
}

// Delete removes a template by id, scoped to the tenant.
func (s *SLATemplateService) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.repo.Delete(ctx, tenantID, id)
}

// DefaultSLATemplates returns the built-in template set every tenant
// starts with: business-critical (latency < 50 ms, loss < 0.1 %),
// real-time (jitter < 15 ms), and best-effort (no SLA).
func DefaultSLATemplates() []SLATemplateInput {
	f := func(v float64) *float64 { return &v }
	return []SLATemplateInput{
		{
			Name:         SLAClassBusinessCritical,
			TrafficClass: SLAClassBusinessCritical,
			MaxLatencyMs: f(50),
			MaxLossPct:   f(0.1),
		},
		{
			Name:         SLAClassRealTime,
			TrafficClass: SLAClassRealTime,
			MaxJitterMs:  f(15),
		},
		{
			Name:         SLAClassBestEffort,
			TrafficClass: SLAClassBestEffort,
		},
	}
}

// EnsureDefaults idempotently creates any of the [DefaultSLATemplates]
// the tenant is missing (matched by name). Returns the full set of
// the tenant's templates after the operation. Safe to call on every
// tenant bootstrap.
func (s *SLATemplateService) EnsureDefaults(ctx context.Context, tenantID uuid.UUID) ([]SLATemplate, error) {
	existing, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	have := make(map[string]struct{}, len(existing))
	for _, t := range existing {
		have[t.Name] = struct{}{}
	}
	for _, in := range DefaultSLATemplates() {
		if _, ok := have[in.Name]; ok {
			continue
		}
		if _, err := s.Create(ctx, tenantID, in); err != nil {
			return nil, err
		}
	}
	return s.List(ctx, tenantID)
}

// SLABundleEntry is one SLA class entry in the compiled SD-WAN bundle
// slice. It is the stable, self-describing cross-language contract the
// enforcement plane consumes.
type SLABundleEntry struct {
	Class               string   `json:"class"`
	Name                string   `json:"name"`
	MaxLatencyMs        *float64 `json:"max_latency_ms,omitempty"`
	MaxLossPct          *float64 `json:"max_loss_pct,omitempty"`
	MaxJitterMs         *float64 `json:"max_jitter_ms,omitempty"`
	MinThroughputMbps   *float64 `json:"min_throughput_mbps,omitempty"`
	ConsecutiveBreaches uint32   `json:"consecutive_breaches"`
}

// SLABundleSlice is the deterministic, ordered set of SLA entries
// embedded in the SD-WAN policy bundle.
type SLABundleSlice []SLABundleEntry

// Compile reads the tenant's SLA templates and compiles them into the
// deterministic SD-WAN bundle slice. Entries are ordered by class then
// name so the byte output is stable across runs (the bundle envelope
// is content-hashed). A best-effort entry with no thresholds compiles
// to an entry with all-null thresholds, which the enforcement plane
// treats as "never violating".
func (s *SLATemplateService) Compile(ctx context.Context, tenantID uuid.UUID) (SLABundleSlice, error) {
	templates, err := s.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	slice := make(SLABundleSlice, 0, len(templates))
	for _, t := range templates {
		slice = append(slice, SLABundleEntry{
			Class:               t.TrafficClass,
			Name:                t.Name,
			MaxLatencyMs:        t.MaxLatencyMs,
			MaxLossPct:          t.MaxLossPct,
			MaxJitterMs:         t.MaxJitterMs,
			MinThroughputMbps:   t.MinThroughputMbps,
			ConsecutiveBreaches: SLADefaultConsecutiveBreaches,
		})
	}
	sort.Slice(slice, func(i, j int) bool {
		if slice[i].Class != slice[j].Class {
			return slice[i].Class < slice[j].Class
		}
		return slice[i].Name < slice[j].Name
	})
	return slice, nil
}

// InMemorySLATemplateRepository is a thread-safe in-memory
// [SLATemplateRepository]. It is the default for tests and for
// deployments that have not yet provisioned the Postgres-backed store;
// it enforces the same tenant-scoping and unique (tenant, name)
// invariants as the SQL schema.
type InMemorySLATemplateRepository struct {
	mu sync.RWMutex
	// byTenant maps tenant -> template id -> template.
	byTenant map[uuid.UUID]map[uuid.UUID]SLATemplate
}

// NewInMemorySLATemplateRepository constructs an empty in-memory
// repository.
func NewInMemorySLATemplateRepository() *InMemorySLATemplateRepository {
	return &InMemorySLATemplateRepository{
		byTenant: make(map[uuid.UUID]map[uuid.UUID]SLATemplate),
	}
}

// Create inserts a new template, rejecting a duplicate (tenant, name).
func (r *InMemorySLATemplateRepository) Create(_ context.Context, tmpl SLATemplate) (SLATemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenant := r.byTenant[tmpl.TenantID]
	for _, existing := range tenant {
		if existing.Name == tmpl.Name {
			return SLATemplate{}, repository.ErrConflict
		}
	}
	if tenant == nil {
		tenant = make(map[uuid.UUID]SLATemplate)
		r.byTenant[tmpl.TenantID] = tenant
	}
	tenant[tmpl.ID] = tmpl
	return tmpl, nil
}

// Get returns a template by id within the tenant.
func (r *InMemorySLATemplateRepository) Get(_ context.Context, tenantID, id uuid.UUID) (SLATemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tmpl, ok := r.byTenant[tenantID][id]
	if !ok {
		return SLATemplate{}, repository.ErrNotFound
	}
	return tmpl, nil
}

// ListByTenant returns all templates for the tenant.
func (r *InMemorySLATemplateRepository) ListByTenant(_ context.Context, tenantID uuid.UUID) ([]SLATemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenant := r.byTenant[tenantID]
	out := make([]SLATemplate, 0, len(tenant))
	for _, tmpl := range tenant {
		out = append(out, tmpl)
	}
	return out, nil
}

// Update replaces an existing template, enforcing the unique
// (tenant, name) constraint against the other rows.
func (r *InMemorySLATemplateRepository) Update(_ context.Context, tmpl SLATemplate) (SLATemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenant := r.byTenant[tmpl.TenantID]
	if _, ok := tenant[tmpl.ID]; !ok {
		return SLATemplate{}, repository.ErrNotFound
	}
	for id, existing := range tenant {
		if id != tmpl.ID && existing.Name == tmpl.Name {
			return SLATemplate{}, repository.ErrConflict
		}
	}
	tenant[tmpl.ID] = tmpl
	return tmpl, nil
}

// Delete removes a template by id within the tenant.
func (r *InMemorySLATemplateRepository) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenant := r.byTenant[tenantID]
	if _, ok := tenant[id]; !ok {
		return repository.ErrNotFound
	}
	delete(tenant, id)
	return nil
}
