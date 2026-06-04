// Package pop implements the control-plane half of Session F's
// Cloud PoP (Point-of-Presence) service: the cloud-delivered
// SWG/DNS/ZTNA edge for tenants that have no on-premise edge VM.
//
// A PoP is a shared, multi-tenant deployment of the `sng-edge`
// binary in a cloud region. This package keeps the registry of PoP
// locations, ingests their health beacons (over NATS), routes
// cloud-only tenants to their nearest healthy PoP (GeoDNS-style),
// and generates the DNS steering records clients resolve during
// enrolment.
//
// Persistence lives in this package rather than the shared
// internal/repository tree on purpose: the PoP feature is
// self-contained and ships as one parallel work-stream, so its
// store is built directly on the production *postgres.ReadWritePool
// using the same withTenant / withSystem / onPrimary transaction
// shapes (and the same RLS GUC `sng.tenant_id`) the repository
// package uses. Reusing the exported pool — rather than copying the
// pool's app-role / PgBouncer plumbing — keeps the RLS + role
// semantics identical to the rest of the control plane.
package pop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// Provider is the cloud provider a PoP runs on. The closed set
// mirrors the CHECK constraint on pops.provider in migration 038.
type Provider string

// Supported cloud providers.
const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// Valid reports whether p is one of the supported providers.
func (p Provider) Valid() bool {
	switch p {
	case ProviderAWS, ProviderGCP, ProviderAzure:
		return true
	default:
		return false
	}
}

// CapacityTier sizes a PoP. It maps to a soft connection ceiling
// the capacity manager uses to decide when a PoP is overloaded.
// The closed set mirrors the CHECK constraint on pops.capacity_tier.
type CapacityTier string

// Supported capacity tiers.
const (
	CapacitySmall  CapacityTier = "small"
	CapacityMedium CapacityTier = "medium"
	CapacityLarge  CapacityTier = "large"
)

// Valid reports whether t is one of the supported tiers.
func (t CapacityTier) Valid() bool {
	switch t {
	case CapacitySmall, CapacityMedium, CapacityLarge:
		return true
	default:
		return false
	}
}

// MaxConnections returns the soft active-connection ceiling for the
// tier. The capacity manager treats a PoP whose latest health beacon
// reports >= this value (scaled by a high-water fraction) as a
// rebalance candidate. Unknown tiers return 0 ("unknown capacity"),
// which the caller treats as "never auto-assign".
func (t CapacityTier) MaxConnections() int {
	switch t {
	case CapacitySmall:
		return 10_000
	case CapacityMedium:
		return 50_000
	case CapacityLarge:
		return 200_000
	default:
		return 0
	}
}

// PoP is a single Point-of-Presence in the global registry.
type PoP struct {
	ID           uuid.UUID
	Region       string
	Provider     Provider
	AnycastIP    string // textual IPv4/IPv6, validated via netip
	DNSName      string
	CapacityTier CapacityTier
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Health is one health beacon for a PoP. Beacons arrive over NATS
// and are persisted to pop_health; the registry keeps the latest
// per PoP in memory for assignment decisions.
type Health struct {
	PoPID             uuid.UUID
	ReportedAt        time.Time
	CPUPct            float64
	MemoryPct         float64
	ActiveConnections int
	BandwidthMbps     float64
}

// Assignment binds a tenant to the PoP that serves it. Exactly one
// per tenant (the table's primary key is tenant_id). Override marks
// an operator-pinned assignment the auto-rebalancer must not touch.
type Assignment struct {
	TenantID   uuid.UUID
	PoPID      uuid.UUID
	AssignedAt time.Time
	Override   bool
}

// Store is the persistence surface for the PoP service. The pops and
// pop_health tables are GLOBAL (no RLS); tenant_pop_assignments is
// tenant-scoped (RLS on sng.tenant_id), so its per-tenant methods run
// under a tenant context and the cross-tenant listing runs under the
// system role.
type Store interface {
	// pops (global)
	CreatePoP(ctx context.Context, p PoP) (PoP, error)
	GetPoP(ctx context.Context, id uuid.UUID) (PoP, error)
	ListPoPs(ctx context.Context, onlyEnabled bool) ([]PoP, error)

	// pop_health (global)
	RecordHealth(ctx context.Context, h Health) error
	LatestHealth(ctx context.Context, popID uuid.UUID) (Health, error)
	LatestHealthAll(ctx context.Context) (map[uuid.UUID]Health, error)

	// tenant_pop_assignments (tenant-scoped via RLS)
	GetAssignment(ctx context.Context, tenantID uuid.UUID) (Assignment, error)
	UpsertAssignment(ctx context.Context, a Assignment) (Assignment, error)

	// ListAssignmentsByPoP runs under the system role (cross-tenant);
	// used only by the capacity rebalancer.
	ListAssignmentsByPoP(ctx context.Context, popID uuid.UUID) ([]Assignment, error)
}

// pgStore is the Postgres-backed Store. It builds directly on the
// production *postgres.ReadWritePool, reusing its exported app-role
// and PgBouncer-mode accessors so its transaction shape matches the
// repository package byte-for-byte.
type pgStore struct {
	pool *postgres.ReadWritePool
}

// NewPostgresStore returns a Store backed by pool. pool must be the
// PRIMARY-capable ReadWritePool the control plane already constructs.
func NewPostgresStore(pool *postgres.ReadWritePool) Store {
	return &pgStore{pool: pool}
}

// --- transaction helpers (mirror internal/repository/postgres/store.go) ---

// setLocalRoleSQL returns the transaction-local role-adoption
// statement when the pool is in PgBouncer mode, matching the
// repository package. In session mode the AfterConnect hook already
// adopted the app role per connection, so this is a no-op.
func (s *pgStore) setLocalRoleSQL() (string, bool) {
	role := s.pool.AppRole()
	if !s.pool.PgBouncerMode() || role == "" {
		return "", false
	}
	return "SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize(), true
}

func (s *pgStore) adoptLocalRole(ctx context.Context, tx pgx.Tx) error {
	sql, ok := s.setLocalRoleSQL()
	if !ok {
		return nil
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("set local role: %w", err)
	}
	return nil
}

// onPrimary runs fn against the primary for a non-RLS (global) query
// — pops / pop_health. In PgBouncer mode it wraps the call in a short
// transaction that first issues SET LOCAL ROLE so the app role is in
// effect; in session mode it runs directly on the pool.
func (s *pgStore) onPrimary(ctx context.Context, fn func(q pgxQuerier) error) error {
	if _, ok := s.setLocalRoleSQL(); !ok {
		return fn(s.pool.Primary())
	}
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// withTenant runs fn inside a transaction whose sng.tenant_id GUC is
// set, so RLS on tenant_pop_assignments scopes the statement.
func (s *pgStore) withTenant(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// withSystem runs fn under sng.system_role='true' so RLS policies
// that honour the system escape hatch allow cross-tenant access.
func (s *pgStore) withSystem(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin system tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.system_role', 'true', true)"); err != nil {
		return fmt.Errorf("set system context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit system tx: %w", err)
	}
	return nil
}

// pgxQuerier is the query subset shared by *pgxpool.Pool and pgx.Tx.
type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// --- error classification ---

func pgErr(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func isUniqueViolation(err error) bool { pe := pgErr(err); return pe != nil && pe.Code == "23505" }
func isCheckViolation(err error) bool  { pe := pgErr(err); return pe != nil && pe.Code == "23514" }
func isForeignKeyViolation(err error) bool {
	pe := pgErr(err)
	return pe != nil && pe.Code == "23503"
}

// classifyWrite maps a write error to the repository sentinels the
// HTTP layer already knows how to render.
func classifyWrite(err error, what string) error {
	switch {
	case isUniqueViolation(err):
		return repository.ErrConflict
	case isCheckViolation(err):
		return repository.ErrInvalidArgument
	case isForeignKeyViolation(err):
		return repository.ErrNotFound
	default:
		return fmt.Errorf("%s: %w", what, err)
	}
}

// --- pops (global) ---

// anycast_ip is an inet column; host() yields the bare address (e.g.
// 203.0.113.10) rather than ::text's CIDR form (203.0.113.10/32), which is
// what callers and GeoDNS A-records expect for a single anycast VIP.
const popColumns = `id, region, provider, host(anycast_ip), dns_name, capacity_tier, enabled, created_at, updated_at`

func scanPoP(row pgx.Row) (PoP, error) {
	var p PoP
	if err := row.Scan(&p.ID, &p.Region, &p.Provider, &p.AnycastIP, &p.DNSName, &p.CapacityTier, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return PoP{}, err
	}
	return p, nil
}

func (s *pgStore) CreatePoP(ctx context.Context, p PoP) (PoP, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	var out PoP
	err := s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `
			INSERT INTO pops (id, region, provider, anycast_ip, dns_name, capacity_tier, enabled)
			VALUES ($1::uuid, $2, $3, $4::inet, $5, $6, $7)
			RETURNING ` + popColumns
		row := q.QueryRow(ctx, sql, p.ID, p.Region, string(p.Provider), p.AnycastIP, p.DNSName, string(p.CapacityTier), p.Enabled)
		var err error
		out, err = scanPoP(row)
		if err != nil {
			return classifyWrite(err, "insert pop")
		}
		return nil
	})
	return out, err
}

func (s *pgStore) GetPoP(ctx context.Context, id uuid.UUID) (PoP, error) {
	var out PoP
	err := s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `SELECT ` + popColumns + ` FROM pops WHERE id = $1::uuid`
		row := q.QueryRow(ctx, sql, id)
		var err error
		out, err = scanPoP(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select pop: %w", err)
		}
		return nil
	})
	return out, err
}

func (s *pgStore) ListPoPs(ctx context.Context, onlyEnabled bool) ([]PoP, error) {
	var out []PoP
	err := s.onPrimary(ctx, func(q pgxQuerier) error {
		sql := `SELECT ` + popColumns + ` FROM pops`
		if onlyEnabled {
			sql += ` WHERE enabled`
		}
		sql += ` ORDER BY region, provider`
		rows, err := q.Query(ctx, sql)
		if err != nil {
			return fmt.Errorf("list pops: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPoP(rows)
			if err != nil {
				return fmt.Errorf("scan pop: %w", err)
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// --- pop_health (global) ---

func (s *pgStore) RecordHealth(ctx context.Context, h Health) error {
	if h.ReportedAt.IsZero() {
		h.ReportedAt = time.Now().UTC()
	}
	return s.onPrimary(ctx, func(q pgxQuerier) error {
		// Upsert on the (pop_id, reported_at) primary key: two beacons
		// that land on the same microsecond (e.g. after future-skew
		// clamping to server time) would otherwise collide and the
		// second would be rejected with ErrConflict, dropping it from
		// both the time-series AND the in-memory registry (IngestHealth
		// only folds on RecordHealth success). Treating an exact-key
		// collision as latest-wins keeps the beacon instead of silently
		// losing it, matching the registry's own latest-wins fold.
		const sql = `
			INSERT INTO pop_health (pop_id, reported_at, cpu_pct, memory_pct, active_connections, bandwidth_mbps)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			ON CONFLICT (pop_id, reported_at) DO UPDATE SET
				cpu_pct = EXCLUDED.cpu_pct,
				memory_pct = EXCLUDED.memory_pct,
				active_connections = EXCLUDED.active_connections,
				bandwidth_mbps = EXCLUDED.bandwidth_mbps`
		_, err := q.Exec(ctx, sql, h.PoPID, h.ReportedAt, h.CPUPct, h.MemoryPct, h.ActiveConnections, h.BandwidthMbps)
		if err != nil {
			return classifyWrite(err, "insert pop_health")
		}
		return nil
	})
}

func scanHealth(row pgx.Row) (Health, error) {
	var h Health
	if err := row.Scan(&h.PoPID, &h.ReportedAt, &h.CPUPct, &h.MemoryPct, &h.ActiveConnections, &h.BandwidthMbps); err != nil {
		return Health{}, err
	}
	return h, nil
}

const healthColumns = `pop_id, reported_at, cpu_pct, memory_pct, active_connections, bandwidth_mbps`

func (s *pgStore) LatestHealth(ctx context.Context, popID uuid.UUID) (Health, error) {
	var out Health
	err := s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `SELECT ` + healthColumns + ` FROM pop_health WHERE pop_id = $1::uuid ORDER BY reported_at DESC LIMIT 1`
		row := q.QueryRow(ctx, sql, popID)
		var err error
		out, err = scanHealth(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select pop_health: %w", err)
		}
		return nil
	})
	return out, err
}

func (s *pgStore) LatestHealthAll(ctx context.Context) (map[uuid.UUID]Health, error) {
	out := make(map[uuid.UUID]Health)
	err := s.onPrimary(ctx, func(q pgxQuerier) error {
		// DISTINCT ON keeps the newest beacon per PoP in one pass.
		const sql = `
			SELECT DISTINCT ON (pop_id) ` + healthColumns + `
			FROM pop_health
			ORDER BY pop_id, reported_at DESC`
		rows, err := q.Query(ctx, sql)
		if err != nil {
			return fmt.Errorf("list pop_health: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanHealth(rows)
			if err != nil {
				return fmt.Errorf("scan pop_health: %w", err)
			}
			out[h.PoPID] = h
		}
		return rows.Err()
	})
	return out, err
}

// --- tenant_pop_assignments (tenant-scoped) ---

func scanAssignment(row pgx.Row) (Assignment, error) {
	var a Assignment
	if err := row.Scan(&a.TenantID, &a.PoPID, &a.AssignedAt, &a.Override); err != nil {
		return Assignment{}, err
	}
	return a, nil
}

const assignmentColumns = `tenant_id, pop_id, assigned_at, override`

func (s *pgStore) GetAssignment(ctx context.Context, tenantID uuid.UUID) (Assignment, error) {
	var out Assignment
	err := s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const sql = `SELECT ` + assignmentColumns + ` FROM tenant_pop_assignments WHERE tenant_id = $1::uuid`
		row := tx.QueryRow(ctx, sql, tenantID)
		var err error
		out, err = scanAssignment(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select assignment: %w", err)
		}
		return nil
	})
	return out, err
}

func (s *pgStore) UpsertAssignment(ctx context.Context, a Assignment) (Assignment, error) {
	var out Assignment
	err := s.withTenant(ctx, a.TenantID.String(), func(tx pgx.Tx) error {
		const sql = `
			INSERT INTO tenant_pop_assignments (tenant_id, pop_id, override)
			VALUES ($1::uuid, $2::uuid, $3)
			ON CONFLICT (tenant_id) DO UPDATE
			   SET pop_id = EXCLUDED.pop_id,
			       override = EXCLUDED.override,
			       assigned_at = now()
			RETURNING ` + assignmentColumns
		row := tx.QueryRow(ctx, sql, a.TenantID, a.PoPID, a.Override)
		var err error
		out, err = scanAssignment(row)
		if err != nil {
			return classifyWrite(err, "upsert assignment")
		}
		return nil
	})
	return out, err
}

func (s *pgStore) ListAssignmentsByPoP(ctx context.Context, popID uuid.UUID) ([]Assignment, error) {
	var out []Assignment
	err := s.withSystem(ctx, func(tx pgx.Tx) error {
		const sql = `SELECT ` + assignmentColumns + ` FROM tenant_pop_assignments WHERE pop_id = $1::uuid ORDER BY assigned_at`
		rows, err := tx.Query(ctx, sql, popID)
		if err != nil {
			return fmt.Errorf("list assignments: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAssignment(rows)
			if err != nil {
				return fmt.Errorf("scan assignment: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// validIP reports whether raw parses as an IP address (IPv4 or IPv6).
func validIP(raw string) bool {
	_, err := netip.ParseAddr(raw)
	return err == nil
}
