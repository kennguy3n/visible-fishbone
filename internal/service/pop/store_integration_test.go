// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build integration

package pop_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/pop"
	"github.com/kennguy3n/visible-fishbone/internal/testutil/pgrole"
)

// appRole mirrors the production "sng_app" non-superuser runtime
// role. RLS (FORCE ROW LEVEL SECURITY) is NOT applied to superusers,
// so the store must run under this role for the tenant-isolation
// assertions to mean anything.
const appRole = "sng_app"

// startStore boots postgres:16-alpine, provisions sng_app, applies
// the embedded migrations (including 038_pops), and returns a
// pop.Store backed by a pool that adopts sng_app on every
// connection — exactly the production transaction shape. It mirrors
// internal/repository/postgres/harness_integration_test.go so the
// PoP store is exercised under the same RLS conditions as the rest
// of the repository layer.
func startStore(t *testing.T) (pop.Store, *postgres.ReadWritePool, func()) {
	t.Helper()
	ctx := context.Background()

	const (
		dbName = "sng"
		user   = "sng"
		pass   = "sng"
	)

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase(dbName),
		tcpostgres.WithUsername(user),
		tcpostgres.WithPassword(pass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}

	bootstrapDSN := fmt.Sprintf(
		"postgres://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)

	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := pgrole.Provision(ctx, bootstrap, appRole, user); err != nil {
		bootstrap.Close()
		t.Fatalf("provision app role: %v", err)
	}
	bootstrap.Close()

	migrateDSN := fmt.Sprintf(
		"pgx5://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)
	runner, err := migrate.New(migrateDSN)
	if err != nil {
		t.Fatalf("migrate runner: %v", err)
	}
	if err := runner.Up(); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate up: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close runner: %v", err)
	}

	poolCfg, err := pgxpool.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatalf("parse pool cfg: %v", err)
	}
	roleIdent := pgx.Identifier{appRole}.Sanitize()
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET SESSION ROLE %s", roleIdent))
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}

	rw := postgres.NewReadWritePool(postgres.ReadWritePoolConfig{
		Primary: pool,
		AppRole: appRole,
	})

	cleanup := func() {
		rw.Close()
		_ = container.Terminate(context.Background())
	}
	return pop.NewPostgresStore(rw), rw, cleanup
}

// seedTenant inserts a tenant row so tenant_pop_assignments' FK is
// satisfiable. The tenants table is global (no RLS), so this runs on
// the primary pool directly.
func seedTenant(t *testing.T, rw *postgres.ReadWritePool, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := rw.Primary().Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug, status, tier) VALUES ($1, $2, $3, 'active', 'starter')`,
		id, name, name+"-"+id.String()[:8])
	if err != nil {
		t.Fatalf("seed tenant %s: %v", name, err)
	}
	return id
}

func mkPoP(region string) pop.PoP {
	return pop.PoP{
		Region:       region,
		Provider:     pop.ProviderAWS,
		AnycastIP:    "203.0.113.10",
		DNSName:      region + ".edge.sng.example.com",
		CapacityTier: pop.CapacityMedium,
		Enabled:      true,
	}
}

func TestStore_PoPLifecycle(t *testing.T) {
	store, _, cleanup := startStore(t)
	defer cleanup()
	ctx := context.Background()

	created, err := store.CreatePoP(ctx, mkPoP("us-east-1"))
	if err != nil {
		t.Fatalf("CreatePoP: %v", err)
	}
	if created.ID == uuid.Nil || created.CreatedAt.IsZero() {
		t.Fatalf("CreatePoP returned unpopulated row: %+v", created)
	}

	got, err := store.GetPoP(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetPoP: %v", err)
	}
	if got.Region != "us-east-1" || got.AnycastIP != "203.0.113.10" {
		t.Fatalf("GetPoP = %+v", got)
	}

	// region+provider uniqueness is enforced by the schema.
	if _, err := store.CreatePoP(ctx, mkPoP("us-east-1")); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("duplicate region/provider err = %v, want ErrConflict", err)
	}

	// A disabled PoP is excluded from the enabled-only listing.
	disabled := mkPoP("eu-west-1")
	disabled.Enabled = false
	if _, err := store.CreatePoP(ctx, disabled); err != nil {
		t.Fatalf("CreatePoP disabled: %v", err)
	}
	enabledOnly, err := store.ListPoPs(ctx, true)
	if err != nil {
		t.Fatalf("ListPoPs(true): %v", err)
	}
	if len(enabledOnly) != 1 || enabledOnly[0].Region != "us-east-1" {
		t.Fatalf("ListPoPs(true) = %+v, want only us-east-1", enabledOnly)
	}
	all, err := store.ListPoPs(ctx, false)
	if err != nil {
		t.Fatalf("ListPoPs(false): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListPoPs(false) returned %d, want 2", len(all))
	}

	if _, err := store.GetPoP(ctx, uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("GetPoP(unknown) err = %v, want ErrNotFound", err)
	}
}

func TestStore_HealthBeacons(t *testing.T) {
	store, _, cleanup := startStore(t)
	defer cleanup()
	ctx := context.Background()

	p, err := store.CreatePoP(ctx, mkPoP("us-east-1"))
	if err != nil {
		t.Fatalf("CreatePoP: %v", err)
	}

	older := pop.Health{PoPID: p.ID, ReportedAt: time.Now().Add(-2 * time.Minute).UTC(), CPUPct: 10, MemoryPct: 20, ActiveConnections: 5, BandwidthMbps: 1}
	newer := pop.Health{PoPID: p.ID, ReportedAt: time.Now().Add(-1 * time.Second).UTC(), CPUPct: 40, MemoryPct: 50, ActiveConnections: 99, BandwidthMbps: 7}
	if err := store.RecordHealth(ctx, older); err != nil {
		t.Fatalf("RecordHealth older: %v", err)
	}
	if err := store.RecordHealth(ctx, newer); err != nil {
		t.Fatalf("RecordHealth newer: %v", err)
	}

	latest, err := store.LatestHealth(ctx, p.ID)
	if err != nil {
		t.Fatalf("LatestHealth: %v", err)
	}
	if latest.ActiveConnections != 99 {
		t.Fatalf("LatestHealth.ActiveConnections = %d, want 99 (newest beacon)", latest.ActiveConnections)
	}

	allHealth, err := store.LatestHealthAll(ctx)
	if err != nil {
		t.Fatalf("LatestHealthAll: %v", err)
	}
	if got := allHealth[p.ID]; got.ActiveConnections != 99 {
		t.Fatalf("LatestHealthAll[p] = %+v, want newest", got)
	}

	if _, err := store.LatestHealth(ctx, uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("LatestHealth(unknown) err = %v, want ErrNotFound", err)
	}

	// Two beacons on the exact same (pop_id, reported_at) must not
	// collide on the primary key: the second is an idempotent
	// latest-wins upsert, not an ErrConflict that would drop the
	// beacon from both the time-series and the in-memory registry.
	sameTS := time.Now().Add(-500 * time.Millisecond).UTC()
	first := pop.Health{PoPID: p.ID, ReportedAt: sameTS, CPUPct: 11, MemoryPct: 22, ActiveConnections: 100, BandwidthMbps: 2}
	second := pop.Health{PoPID: p.ID, ReportedAt: sameTS, CPUPct: 33, MemoryPct: 44, ActiveConnections: 250, BandwidthMbps: 9}
	if err := store.RecordHealth(ctx, first); err != nil {
		t.Fatalf("RecordHealth first same-ts: %v", err)
	}
	if err := store.RecordHealth(ctx, second); err != nil {
		t.Fatalf("RecordHealth second same-ts must upsert, not conflict: %v", err)
	}
	latest, err = store.LatestHealth(ctx, p.ID)
	if err != nil {
		t.Fatalf("LatestHealth after upsert: %v", err)
	}
	if latest.ActiveConnections != 250 {
		t.Fatalf("LatestHealth.ActiveConnections = %d, want 250 (upserted beacon won)", latest.ActiveConnections)
	}
}

// TestStore_AssignmentRLSIsolation is the load-bearing security
// test: tenant_pop_assignments is RLS-scoped, so a query bound to
// tenant A must never see tenant B's assignment, while the system
// role (the rebalancer) sees both.
func TestStore_AssignmentRLSIsolation(t *testing.T) {
	store, rw, cleanup := startStore(t)
	defer cleanup()
	ctx := context.Background()

	p, err := store.CreatePoP(ctx, mkPoP("us-east-1"))
	if err != nil {
		t.Fatalf("CreatePoP: %v", err)
	}
	tenantA := seedTenant(t, rw, "alpha")
	tenantB := seedTenant(t, rw, "bravo")

	if _, err := store.UpsertAssignment(ctx, pop.Assignment{TenantID: tenantA, PoPID: p.ID, Override: false}); err != nil {
		t.Fatalf("UpsertAssignment A: %v", err)
	}
	if _, err := store.UpsertAssignment(ctx, pop.Assignment{TenantID: tenantB, PoPID: p.ID, Override: true}); err != nil {
		t.Fatalf("UpsertAssignment B: %v", err)
	}

	// Each tenant sees only its own row.
	gotA, err := store.GetAssignment(ctx, tenantA)
	if err != nil {
		t.Fatalf("GetAssignment A: %v", err)
	}
	if gotA.TenantID != tenantA || gotA.Override {
		t.Fatalf("GetAssignment A = %+v", gotA)
	}
	gotB, err := store.GetAssignment(ctx, tenantB)
	if err != nil {
		t.Fatalf("GetAssignment B: %v", err)
	}
	if gotB.TenantID != tenantB || !gotB.Override {
		t.Fatalf("GetAssignment B = %+v", gotB)
	}

	// A tenant with no assignment gets ErrNotFound — RLS hides
	// every other tenant's row, so the lookup is genuinely empty.
	if _, err := store.GetAssignment(ctx, seedTenant(t, rw, "charlie")); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("GetAssignment(unassigned) err = %v, want ErrNotFound", err)
	}

	// The system-role cross-tenant listing (used by the rebalancer)
	// sees BOTH tenants' assignments for the PoP.
	byPoP, err := store.ListAssignmentsByPoP(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListAssignmentsByPoP: %v", err)
	}
	if len(byPoP) != 2 {
		t.Fatalf("ListAssignmentsByPoP returned %d, want 2 (system role sees all tenants)", len(byPoP))
	}
	seen := map[uuid.UUID]bool{}
	for _, a := range byPoP {
		seen[a.TenantID] = true
	}
	if !seen[tenantA] || !seen[tenantB] {
		t.Fatalf("ListAssignmentsByPoP missing a tenant: %+v", byPoP)
	}
}

func TestStore_UpsertAssignmentReassigns(t *testing.T) {
	store, rw, cleanup := startStore(t)
	defer cleanup()
	ctx := context.Background()

	p1, err := store.CreatePoP(ctx, mkPoP("us-east-1"))
	if err != nil {
		t.Fatalf("CreatePoP p1: %v", err)
	}
	p2, err := store.CreatePoP(ctx, mkPoP("us-west-2"))
	if err != nil {
		t.Fatalf("CreatePoP p2: %v", err)
	}
	tenant := seedTenant(t, rw, "delta")

	if _, err := store.UpsertAssignment(ctx, pop.Assignment{TenantID: tenant, PoPID: p1.ID}); err != nil {
		t.Fatalf("UpsertAssignment initial: %v", err)
	}
	// Re-home: the PK is tenant_id, so a second upsert moves the
	// tenant rather than creating a duplicate.
	if _, err := store.UpsertAssignment(ctx, pop.Assignment{TenantID: tenant, PoPID: p2.ID, Override: true}); err != nil {
		t.Fatalf("UpsertAssignment rehome: %v", err)
	}
	got, err := store.GetAssignment(ctx, tenant)
	if err != nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if got.PoPID != p2.ID || !got.Override {
		t.Fatalf("GetAssignment = %+v, want pop=%s override=true", got, p2.ID)
	}

	// FK violation: assigning to a non-existent PoP maps to ErrNotFound.
	if _, err := store.UpsertAssignment(ctx, pop.Assignment{TenantID: tenant, PoPID: uuid.New()}); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpsertAssignment(bad pop) err = %v, want ErrNotFound", err)
	}
}
