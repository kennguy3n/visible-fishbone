//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/testutil/pgrole"
)

// appLoginRole is an unprivileged LOGIN role that is NOINHERIT and a
// member of appRole. It mirrors the production PgBouncer posture
// (docs/deploy.md): the connection authenticates as a login role
// that holds *no* table privileges of its own and must `SET ROLE
// sng_app` to do any work. Because it is NOINHERIT, the membership
// confers nothing until an explicit SET ROLE — exactly the
// condition under which a forgotten role adoption surfaces as
// "permission denied".
const (
	appLoginRole = "sng_app_login"
	appLoginPass = "applogin"
)

// pgSQLStatePermissionDenied is the SQLSTATE Postgres raises for an
// INSUFFICIENT PRIVILEGE error (e.g. a table the current role lacks
// DML on). https://www.postgresql.org/docs/16/errcodes-appendix.html
const pgSQLStatePermissionDenied = "42501"

// startPostgresPgBouncer boots the same schema as startPostgres but
// returns a Store configured for PgBouncer (transaction-pooling)
// mode: the pool connects as the unprivileged appLoginRole with NO
// AfterConnect `SET SESSION ROLE` hook, and the Store is told to
// adopt appRole transaction-locally (SET LOCAL ROLE) instead. This
// is the exact configuration in which the direct-pool MSP/Role/
// Tenant queries must route through Store.onPrimary to pick up the
// app role — without it every such query runs as appLoginRole and
// is denied.
func startPostgresPgBouncer(t *testing.T) (*postgres.Store, func()) {
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

	// Provision the runtime role BEFORE migrations (002 requires it),
	// then create the unprivileged LOGIN role and grant it membership
	// in appRole so its `SET LOCAL ROLE appRole` will succeed.
	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := pgrole.Provision(ctx, bootstrap, appRole, user); err != nil {
		bootstrap.Close()
		t.Fatalf("provision app role: %v", err)
	}
	// LOGIN + NOINHERIT: the role can connect but inherits none of
	// appRole's privileges implicitly; it must SET ROLE to use them.
	if _, err := bootstrap.Exec(ctx,
		fmt.Sprintf("CREATE ROLE %s LOGIN NOINHERIT PASSWORD '%s'", appLoginRole, appLoginPass),
	); err != nil {
		bootstrap.Close()
		t.Fatalf("create login role: %v", err)
	}
	if _, err := bootstrap.Exec(ctx,
		fmt.Sprintf("GRANT %s TO %s", appRole, appLoginRole),
	); err != nil {
		bootstrap.Close()
		t.Fatalf("grant app role membership: %v", err)
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

	// The application pool connects as the unprivileged login role
	// and installs NO AfterConnect hook — exactly what PgBouncer
	// transaction-pooling mode requires (a session-level SET SESSION
	// ROLE would leak across multiplexed server connections).
	appDSN := fmt.Sprintf(
		"postgres://%s@%s/%s?sslmode=disable",
		url.UserPassword(appLoginRole, appLoginPass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)
	poolCfg, err := pgxpool.ParseConfig(appDSN)
	if err != nil {
		t.Fatalf("parse pool cfg: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}

	store := postgres.NewStoreWithPool(postgres.NewReadWritePool(postgres.ReadWritePoolConfig{
		Primary:       pool,
		AppRole:       appRole,
		PgBouncerMode: true,
	}))

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(context.Background())
	}
	return store, cleanup
}

// TestPgBouncerMode_DirectPoolRoleAdoption proves that the
// standalone (non-tenant-scoped) MSP/Role/Tenant queries adopt the
// app role in PgBouncer mode. Each repo CRUD call below issues its
// query through Store.onPrimary, which opens a short transaction and
// runs SET LOCAL ROLE before the statement. Without that routing the
// queries would execute as the unprivileged appLoginRole and fail
// with permission denied — which the control assertion confirms is
// the bare-connection behaviour.
func TestPgBouncerMode_DirectPoolRoleAdoption(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgresPgBouncer(t)
	t.Cleanup(cleanup)
	ctx := context.Background()

	// Control: a raw INSERT on the bare pooled connection (bypassing
	// onPrimary, so no SET LOCAL ROLE) must be denied. This proves
	// the login role is genuinely unprivileged, so any success below
	// is attributable to role adoption rather than an over-privileged
	// test user.
	_, rawErr := store.Pool().Exec(ctx,
		`INSERT INTO msps (id, name, slug, status, branding, settings)
		 VALUES ($1::uuid, $2, $3, $4, '{}'::jsonb, '{}'::jsonb)`,
		uuid.New(), "control", "raw-control-"+uuid.NewString()[:8], string(repository.MSPStatusActive),
	)
	var pgErr *pgconn.PgError
	if !errors.As(rawErr, &pgErr) || pgErr.Code != pgSQLStatePermissionDenied {
		t.Fatalf("control: want permission denied (%s) for raw login-role insert, got %v",
			pgSQLStatePermissionDenied, rawErr)
	}

	t.Run("MSP", func(t *testing.T) {
		repo := store.NewMSPRepository()
		slug := "msp-" + uuid.NewString()[:8]
		created, err := repo.Create(ctx, repository.MSP{
			Name: slug, Slug: slug, Status: repository.MSPStatusActive,
		})
		if err != nil {
			t.Fatalf("create msp (role adoption failed?): %v", err)
		}
		got, err := repo.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("get msp: %v", err)
		}
		if got.Slug != slug {
			t.Errorf("get msp slug: want %q got %q", slug, got.Slug)
		}
		if _, err := repo.GetBySlug(ctx, slug); err != nil {
			t.Fatalf("get msp by slug: %v", err)
		}
		if _, err := repo.List(ctx, repository.Page{Limit: 10}, repository.MSPListFilter{}); err != nil {
			t.Fatalf("list msps: %v", err)
		}
	})

	t.Run("Tenant", func(t *testing.T) {
		repo := store.NewTenantRepository()
		// Tenant.Create opens a raw BeginTx; this exercises the
		// adoptLocalRole call added at the top of that transaction.
		slug := "tnt-" + uuid.NewString()[:8]
		created, err := repo.Create(ctx, repository.Tenant{
			Name: slug, Slug: slug, Tier: repository.TenantTierStarter,
		})
		if err != nil {
			t.Fatalf("create tenant (Create adoptLocalRole missing?): %v", err)
		}
		if _, err := repo.Get(ctx, created.ID); err != nil {
			t.Fatalf("get tenant: %v", err)
		}
		if _, err := repo.GetBySlug(ctx, slug); err != nil {
			t.Fatalf("get tenant by slug: %v", err)
		}
		if _, err := repo.List(ctx, repository.Page{Limit: 10}); err != nil {
			t.Fatalf("list tenants: %v", err)
		}
		newName := "renamed-" + uuid.NewString()[:6]
		if _, err := repo.Update(ctx, created.ID, repository.TenantPatch{Name: &newName}); err != nil {
			t.Fatalf("update tenant: %v", err)
		}
	})

	t.Run("Role", func(t *testing.T) {
		tr := store.NewTenantRepository()
		ur := store.NewUserRepository()
		rr := store.NewRoleRepository()

		tslug := "rt-" + uuid.NewString()[:8]
		tnt, err := tr.Create(ctx, repository.Tenant{
			Name: tslug, Slug: tslug, Tier: repository.TenantTierStarter,
		})
		if err != nil {
			t.Fatalf("create tenant for role: %v", err)
		}
		usr, err := ur.Create(ctx, tnt.ID, repository.User{Email: "u@" + tnt.Slug + ".test"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		role, err := rr.Create(ctx, repository.Role{
			TenantID:    &tnt.ID,
			Name:        "ops-" + uuid.NewString()[:6],
			Permissions: []string{"devices:read"},
			Scope:       repository.RoleScopeTenant,
		})
		if err != nil {
			t.Fatalf("create role (role adoption failed?): %v", err)
		}
		if _, err := rr.Get(ctx, role.ID); err != nil {
			t.Fatalf("get role: %v", err)
		}
		if err := rr.AssignRole(ctx, repository.UserRole{UserID: usr.ID, RoleID: role.ID}); err != nil {
			t.Fatalf("assign role: %v", err)
		}
		ok, err := rr.HasPermission(ctx, usr.ID, "devices:read")
		if err != nil {
			t.Fatalf("has permission: %v", err)
		}
		if !ok {
			t.Error("has permission: want true")
		}
	})
}
