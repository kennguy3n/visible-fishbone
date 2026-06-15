package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// dem.go is the durability boundary for Digital Experience
// Monitoring (DEM) — the Zscaler ZDX-style end-to-end experience
// signal. It is a NEW file (mirroring threat_ioc.go) so the WP5
// work package never co-edits the shared interfaces.go /
// types.go surfaces.
//
// The four row types are neutral, primitive-typed projections of
// the domain values the internal/service/dem package owns; the
// data layer deliberately does not import the service package.
// Every row is keyed by a stable `target_key` rather than a
// foreign key to dem_targets, because the managed default targets
// are code-defined (they have no config row) — see migration 091.

// DEMProbeKind is the probe transport, mirroring the edge
// `sng-dem` crate's ProbeKind tokens. Kept as a string-typed
// projection here; the service validates the value.
type DEMProbeKind = string

// DEMTarget is one persisted per-tenant custom probe target. It
// layers on top of the code-defined managed default set: a tenant
// adds rows here only to probe endpoints the defaults do not
// cover, or to disable/override a default by reusing its key.
type DEMTarget struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	TargetKey string
	Name      string
	ProbeKind DEMProbeKind
	Address   string
	// Port is the TCP port for tcp probes (http/https derive it
	// from the URL); nil persists as NULL.
	Port            *int
	Enabled         bool
	IntervalSeconds int
	TimeoutMs       int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DEMProbeResult is one raw probe sample ingested from the edge.
// A failed probe is a first-class row (Success=false with an
// ErrorKind), never an absence of data. The optional timing
// pointers are nil when the probe did not reach that phase.
type DEMProbeResult struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	TargetKey  string
	TargetName string
	ProbeKind  DEMProbeKind
	Success    bool
	DNSMs      *float64
	TCPMs      *float64
	TLSMs      *float64
	TTFBMs     *float64
	TotalMs    *float64
	HTTPStatus *int
	// ErrorKind is the failure bucket ("timeout", "dns",
	// "connect", "tls", "http", "config", "internal"); empty
	// persists as NULL.
	ErrorKind  string
	ObservedAt time.Time
	CreatedAt  time.Time
}

// DEMExperienceScore is one per-window experience-score sample:
// a composite 0..100 score plus the aggregates it was derived
// from. This is the durable timeseries the UI charts.
type DEMExperienceScore struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	TargetKey     string
	TargetName    string
	Score         float64
	Availability  float64
	LatencyP50Ms  *float64
	LatencyP95Ms  *float64
	SampleCount   int
	WindowSeconds int
	WindowStart   time.Time
	WindowEnd     time.Time
	CreatedAt     time.Time
}

// DEMTargetState is the per-(tenant, target) rolling baseline +
// alert bookkeeping: exactly one row per target. EWMAScore /
// EWMAVariance form the adaptive baseline degradation detection
// compares each new score against; LastAlertAt enforces the alert
// cooldown.
type DEMTargetState struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	TargetKey      string
	TargetName     string
	EWMAScore      *float64
	EWMAVariance   *float64
	LastScore      *float64
	SampleCount    int64
	Degraded       bool
	LastAlertAt    *time.Time
	LastObservedAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DEMWindowAggregate is the rolling-window rollup of raw results
// for one target, computed at the data layer (percentiles in SQL
// on Postgres, in Go on the memory backend). SampleCount==0 means
// the window is empty and no score should be produced.
type DEMWindowAggregate struct {
	TargetKey    string
	SampleCount  int
	SuccessCount int
	LatencyP50Ms *float64
	LatencyP95Ms *float64
	WindowStart  time.Time
	WindowEnd    time.Time
}

// DEMScoreFilter narrows a score listing. Empty TargetKeys matches
// every target; zero Since/Until disable that bound.
type DEMScoreFilter struct {
	TargetKeys []string
	Since      time.Time
	Until      time.Time
}

// DEMRepository is the persistence surface for DEM. Target CRUD,
// score listing, and the window aggregate are tenant-scoped (RLS
// via sng.tenant_id); the retention prunes run cross-tenant under
// the system role.
type DEMRepository interface {
	// --- Targets (tenant custom config) ---

	// CreateTarget persists a new custom target. Returns
	// ErrConflict when (tenant, target_key) already exists and
	// ErrInvalidArgument on a malformed row.
	CreateTarget(ctx context.Context, tenantID uuid.UUID, t DEMTarget) (DEMTarget, error)
	// GetTarget returns one target by id, scoped to tenant.
	// ErrNotFound when absent.
	GetTarget(ctx context.Context, tenantID, id uuid.UUID) (DEMTarget, error)
	// UpdateTarget mutates the addressable fields (name, address,
	// port, enabled, interval, timeout) of an existing target by
	// id. ErrNotFound when absent.
	UpdateTarget(ctx context.Context, tenantID uuid.UUID, t DEMTarget) (DEMTarget, error)
	// DeleteTarget removes a custom target by id. ErrNotFound when
	// absent.
	DeleteTarget(ctx context.Context, tenantID, id uuid.UUID) error
	// ListTargets enumerates a tenant's custom targets in
	// created-at order.
	ListTargets(ctx context.Context, tenantID uuid.UUID, page Page) (PageResult[DEMTarget], error)

	// --- Raw probe results ---

	// InsertProbeResults bulk-inserts ingested samples for one
	// tenant in a single transaction. An empty slice is a no-op.
	InsertProbeResults(ctx context.Context, tenantID uuid.UUID, results []DEMProbeResult) error
	// WindowAggregate rolls up the results for one target observed
	// at or after `since` into availability + latency percentiles.
	WindowAggregate(ctx context.Context, tenantID uuid.UUID, targetKey string, since time.Time) (DEMWindowAggregate, error)
	// PruneProbeResults deletes raw results created before
	// `before` across all tenants (system role). Returns the row
	// count removed.
	PruneProbeResults(ctx context.Context, before time.Time) (int64, error)

	// --- Experience scores ---

	// InsertScore appends one experience-score sample.
	InsertScore(ctx context.Context, tenantID uuid.UUID, s DEMExperienceScore) (DEMExperienceScore, error)
	// ListScores enumerates score samples matching the filter in
	// created-at order (keyset paginated).
	ListScores(ctx context.Context, tenantID uuid.UUID, filter DEMScoreFilter, page Page) (PageResult[DEMExperienceScore], error)
	// LatestScores returns the most recent score sample per target
	// for a tenant (one row per target_key), newest first.
	LatestScores(ctx context.Context, tenantID uuid.UUID) ([]DEMExperienceScore, error)
	// PruneScores deletes score samples created before `before`
	// across all tenants (system role). Returns the row count
	// removed.
	PruneScores(ctx context.Context, before time.Time) (int64, error)

	// --- Per-target rolling state ---

	// GetTargetState returns the baseline row for (tenant,
	// target_key). The bool is false (with a nil error) when no
	// row exists yet.
	GetTargetState(ctx context.Context, tenantID uuid.UUID, targetKey string) (DEMTargetState, bool, error)
	// UpsertTargetState inserts or updates the baseline row,
	// keyed by (tenant, target_key).
	UpsertTargetState(ctx context.Context, tenantID uuid.UUID, st DEMTargetState) (DEMTargetState, error)
}
