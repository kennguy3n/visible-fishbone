//go:build integration

package metering_test

import (
	"context"
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
	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
	"github.com/kennguy3n/visible-fishbone/internal/testutil/pgrole"
)

const appRole = "sng_app"

// meteringHarness bundles the app-role pool (RLS-enforced, as the
// runtime sees it) and a superuser bootstrap pool used only to seed
// the parent `tenants` rows the FK requires.
type meteringHarness struct {
	store     *metering.PostgresStore
	appPool   *pgxpool.Pool
	bootstrap *pgxpool.Pool
}

// startMeteringPostgres boots postgres:16-alpine, provisions the
// non-superuser app role, applies the embedded migrations (including
// 040_metering), and opens an app-role pool. Mirrors the harness in
// internal/repository/postgres so RLS is exercised exactly as in prod.
func startMeteringPostgres(t *testing.T) (*meteringHarness, func()) {
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

	migrateDSN := fmt.Sprintf(
		"pgx5://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)
	runner, err := migrate.New(migrateDSN)
	if err != nil {
		bootstrap.Close()
		t.Fatalf("migrate runner: %v", err)
	}
	if err := runner.Up(); err != nil {
		_ = runner.Close()
		bootstrap.Close()
		t.Fatalf("migrate up: %v", err)
	}
	if err := runner.Close(); err != nil {
		bootstrap.Close()
		t.Fatalf("close runner: %v", err)
	}

	poolCfg, err := pgxpool.ParseConfig(bootstrapDSN)
	if err != nil {
		bootstrap.Close()
		t.Fatalf("parse pool cfg: %v", err)
	}
	roleIdent := pgx.Identifier{appRole}.Sanitize()
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET SESSION ROLE %s", roleIdent))
		return err
	}
	appPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		bootstrap.Close()
		t.Fatalf("open app pool: %v", err)
	}

	store, err := metering.NewPostgresStore(appPool, appRole, false)
	if err != nil {
		appPool.Close()
		bootstrap.Close()
		t.Fatalf("new store: %v", err)
	}

	cleanup := func() {
		appPool.Close()
		bootstrap.Close()
		_ = container.Terminate(context.Background())
	}
	return &meteringHarness{store: store, appPool: appPool, bootstrap: bootstrap}, cleanup
}

// seedTenant inserts a tenant row via the superuser bootstrap pool
// (which bypasses RLS) so the tenant_usage / tenant_budgets FK is
// satisfied.
func (h *meteringHarness) seedTenant(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := h.bootstrap.Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug, status, tier) VALUES ($1, $2, $3, 'active', 'starter')`,
		id, "T-"+slug, slug)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

func TestPostgresStoreBatchUpsertIsAdditive(t *testing.T) {
	h, cleanup := startMeteringPostgres(t)
	defer cleanup()
	ctx := context.Background()
	tid := h.seedTenant(t, "additive")

	start, end := metering.PeriodMonthly.Bounds(time.Now())
	d := metering.UsageDelta{TenantID: tid, Meter: metering.MeterLLMTokensUsed, PeriodStart: start, PeriodEnd: end, Delta: 100}

	if err := h.store.BatchUpsertUsage(ctx, []metering.UsageDelta{d}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// Same key again: must ADD, not overwrite.
	d.Delta = 250
	if err := h.store.BatchUpsertUsage(ctx, []metering.UsageDelta{d}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, err := h.store.TenantPeriodUsage(ctx, tid, metering.MeterLLMTokensUsed, start)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != 350 {
		t.Fatalf("value = %d, want 350 (additive upsert)", got)
	}
}

func TestPostgresStoreRLSIsolatesTenants(t *testing.T) {
	h, cleanup := startMeteringPostgres(t)
	defer cleanup()
	ctx := context.Background()
	tA := h.seedTenant(t, "rls-a")
	tB := h.seedTenant(t, "rls-b")

	start, end := metering.PeriodMonthly.Bounds(time.Now())
	if err := h.store.BatchUpsertUsage(ctx, []metering.UsageDelta{
		{TenantID: tA, Meter: metering.MeterLLMCalls, PeriodStart: start, PeriodEnd: end, Delta: 10},
		{TenantID: tB, Meter: metering.MeterLLMCalls, PeriodStart: start, PeriodEnd: end, Delta: 20},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	// Tenant-scoped read for A must see only A's row.
	recs, err := h.store.TenantCurrentUsage(ctx, tA, time.Now())
	if err != nil {
		t.Fatalf("current usage A: %v", err)
	}
	for _, r := range recs {
		if r.TenantID != tA {
			t.Fatalf("RLS leak: tenant A read returned tenant %s", r.TenantID)
		}
	}
	if len(recs) != 1 || recs[0].Value != 10 {
		t.Fatalf("tenant A usage = %+v, want single row value 10", recs)
	}
}

func TestPostgresStoreSystemRoleSeesAllTenants(t *testing.T) {
	h, cleanup := startMeteringPostgres(t)
	defer cleanup()
	ctx := context.Background()
	tA := h.seedTenant(t, "sys-a")
	tB := h.seedTenant(t, "sys-b")

	start, end := metering.PeriodMonthly.Bounds(time.Now())
	if err := h.store.BatchUpsertUsage(ctx, []metering.UsageDelta{
		{TenantID: tA, Meter: metering.MeterURLCatLookups, PeriodStart: start, PeriodEnd: end, Delta: 5},
		{TenantID: tB, Meter: metering.MeterURLCatLookups, PeriodStart: start, PeriodEnd: end, Delta: 7},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	// System-scoped platform read must cross tenant boundaries.
	rows, err := h.store.PlatformCurrentUsage(ctx, time.Now())
	if err != nil {
		t.Fatalf("platform usage: %v", err)
	}
	seen := map[uuid.UUID]int64{}
	for _, r := range rows {
		seen[r.TenantID] += r.Value
	}
	if seen[tA] != 5 || seen[tB] != 7 {
		t.Fatalf("platform read = %+v, want A=5 B=7", seen)
	}
}

func TestPostgresStoreBudgetRoundTrip(t *testing.T) {
	h, cleanup := startMeteringPostgres(t)
	defer cleanup()
	ctx := context.Background()
	tid := h.seedTenant(t, "budget")

	lim := metering.BudgetLimit{Meter: metering.MeterLLMCalls, SoftLimit: 80, HardLimit: 100, Period: metering.PeriodMonthly}
	if err := h.store.UpsertTenantBudget(ctx, tid, lim); err != nil {
		t.Fatalf("upsert budget: %v", err)
	}
	// Upsert again with new limits — must replace, not duplicate.
	lim.SoftLimit, lim.HardLimit = 800, 1000
	if err := h.store.UpsertTenantBudget(ctx, tid, lim); err != nil {
		t.Fatalf("re-upsert budget: %v", err)
	}
	budgets, err := h.store.TenantBudgets(ctx, tid)
	if err != nil {
		t.Fatalf("read budgets: %v", err)
	}
	if len(budgets) != 1 {
		t.Fatalf("budget rows = %d, want 1 (upsert replaced)", len(budgets))
	}
	if budgets[0].HardLimit != 1000 || budgets[0].SoftLimit != 800 {
		t.Fatalf("budget = %+v, want soft 800 hard 1000", budgets[0])
	}
}

func TestPostgresStoreNilPoolRejected(t *testing.T) {
	if _, err := metering.NewPostgresStore(nil, appRole, false); err == nil {
		t.Fatal("expected error for nil pool")
	}
}
