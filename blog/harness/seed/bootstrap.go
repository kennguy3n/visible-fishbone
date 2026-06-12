// bootstrap.go provisions the two pieces of state the API-driven seed
// run cannot create for itself, so `go run ./blog/harness/seed` is
// fully reproducible against a freshly-migrated database.
//
//  1. Platform RBAC grant. The seed and capture harnesses act as a
//     global platform operator (a JWT with roles:["platform_admin"] and
//     no tenant_id claim). The control plane authorises the
//     platform-scoped routes — POST/GET /api/v1/msps, the admin
//     cost-report, the global audit log — via the *database-backed* RBAC
//     store (rbac.Service.AuthorizePlatform reads user_roles), NOT the
//     JWT roles claim. A fresh database has no role grants, so those
//     routes return 403 platform_forbidden and the MSP onboarding step
//     (S1 evidence) fails. This is a genuine bootstrap chicken-and-egg:
//     you cannot grant yourself platform authority through an API that
//     already requires it. We therefore seed the operator user and its
//     platform_admin grant directly. RBAC enforcement is unchanged — the
//     operator is authorised through the same real grant a production
//     deployment would provision for its first platform admin.
//
//  2. Canonical fixture identities. The tenant create API deliberately
//     does not accept a client-supplied id (server-assigned UUIDs only),
//     but the capture/usage/anomalies harnesses, the committed payloads,
//     and the blog posts all reference four stable tenant UUIDs (and the
//     MSP UUID). Seeding those identity rows here keeps the whole
//     pipeline deterministic across reruns and fresh databases; every
//     business sub-resource (sites, devices, policies, DLP, …) is still
//     created through the real operator API by the rest of the harness.
//
// All inserts are idempotent (ON CONFLICT DO NOTHING) and run as the
// owning login role with the RLS GUC set for the users insert, exactly
// as the control plane does its own writes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/visible-fishbone/blog/harness/fleet"
)

// The canonical tenant, platform and MSP identities the rest of the
// pipeline (capture/usage/anomalies/casb harnesses, payloads, blog posts)
// references live in the shared fleet package — the single source of
// truth. bootstrap.go pins those identities into the database; only
// platformAdminRoleID, which is RBAC scaffolding rather than tenant
// identity, is local.
//
// platformAdminRoleID is a fixed id for the platform_admin role so reruns
// never create a duplicate grant target.
const platformAdminRoleID = "a0000000-0000-4000-8000-000000000001"

// bootstrapFixtures seeds the platform RBAC grant and the canonical
// fixture identities. It is safe to run repeatedly.
func bootstrapFixtures(ctx context.Context, operatorID string) error {
	pool, err := openSeedPool(ctx)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. platform_admin role (scope=platform, wildcard permission).
	if _, err := tx.Exec(ctx, `
		INSERT INTO roles (id, tenant_id, name, permissions, scope)
		VALUES ($1::uuid, NULL, 'platform_admin', '["*"]'::jsonb, 'platform')
		ON CONFLICT (id) DO NOTHING`, platformAdminRoleID); err != nil {
		return fmt.Errorf("seed platform_admin role: %w", err)
	}

	// 2. canonical tenant identity rows. Slug is UNIQUE; on a fresh
	// database this assigns the pinned UUID, and reruns are no-ops.
	for _, t := range scenarioTenants() {
		ft, ok := fleet.BySlug(t.slug)
		if !ok {
			return fmt.Errorf("no canonical id pinned for tenant slug %q", t.slug)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenants (id, name, slug, status, region, tier)
			VALUES ($1::uuid, $2, $3, 'active', NULLIF($4, ''), $5)
			ON CONFLICT (slug) DO NOTHING`,
			ft.ID, t.name, t.slug, t.region, t.tier); err != nil {
			return fmt.Errorf("seed tenant %s: %w", t.slug, err)
		}
	}

	// 2b. platform (system) tenant. Not part of scenarioTenants() — it
	// is the operator's home and an expected row in GET /tenants — so it
	// is pinned to its own stable UUID here.
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, status, tier)
		VALUES ($1::uuid, $2, $3, 'active', $4)
		ON CONFLICT (slug) DO NOTHING`,
		fleet.PlatformTenantID, fleet.PlatformTenantName, fleet.PlatformTenantSlug, fleet.PlatformTenantTier); err != nil {
		return fmt.Errorf("seed platform tenant: %w", err)
	}

	// 3. canonical MSP identity row; ensureMSP() reuses it by slug.
	if _, err := tx.Exec(ctx, `
		INSERT INTO msps (id, name, slug, status)
		VALUES ($1::uuid, $2, $3, 'active')
		ON CONFLICT (id) DO NOTHING`, fleet.MSPID, fleet.MSPName, fleet.MSPSlug); err != nil {
		return fmt.Errorf("seed msp: %w", err)
	}

	// 4. operator user, homed in the platform tenant. users is
	// RLS-FORCEd, so set the tenant GUC for this statement exactly as
	// the control plane does before writing.
	homeID := fleet.PlatformTenantID
	if _, err := tx.Exec(ctx, `SELECT set_config('sng.tenant_id', $1, true)`, homeID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, status)
		VALUES ($1::uuid, $2::uuid, 'operator@shieldnet.dev', 'Platform Operator', 'active')
		ON CONFLICT (id) DO NOTHING`, operatorID, homeID); err != nil {
		return fmt.Errorf("seed operator user: %w", err)
	}

	// 5. grant platform_admin to the operator.
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, scope_id)
		VALUES ($1::uuid, $2::uuid, NULL)
		ON CONFLICT DO NOTHING`, operatorID, platformAdminRoleID); err != nil {
		return fmt.Errorf("grant platform_admin: %w", err)
	}

	// 6. tenant.created provisioning audit. The control plane writes a
	// tenant.created audit_log row scoped to the new tenant on every
	// create (tenant/service.go Create -> appendAudit, with a nil actor
	// and empty details). Because bootstrap pins the canonical tenant
	// identities via direct SQL — the create API assigns server-side
	// UUIDs and cannot honour the pinned ids the rest of the pipeline
	// references — that provisioning event would otherwise be missing,
	// leaving each tenant's audit trail with no record of its own
	// creation. We restore the exact row a production onboarding writes
	// so the S1 audit evidence stays complete. created_at defaults to
	// NOW(); bootstrap runs before any API-driven seeding, so this is
	// naturally the earliest event in each tenant's trail. audit_log is
	// RLS-FORCEd, so the per-tenant GUC is set before each write, and the
	// NOT EXISTS guard keeps reruns idempotent.
	auditTenantIDs := make([]string, 0, len(fleet.All())+1)
	for _, t := range fleet.All() {
		auditTenantIDs = append(auditTenantIDs, t.ID)
	}
	auditTenantIDs = append(auditTenantIDs, fleet.PlatformTenantID)
	for _, id := range auditTenantIDs {
		if _, err := tx.Exec(ctx, `SELECT set_config('sng.tenant_id', $1, true)`, id); err != nil {
			return fmt.Errorf("set tenant context for audit %s: %w", id, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_log (tenant_id, action, resource_type, resource_id, details)
			SELECT $1::uuid, 'tenant.created', 'tenant', $1::uuid, '{}'::jsonb
			WHERE NOT EXISTS (
				SELECT 1 FROM audit_log
				WHERE tenant_id = $1::uuid AND action = 'tenant.created'
			)`, id); err != nil {
			return fmt.Errorf("seed tenant.created audit for %s: %w", id, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	// Verify the canonical ids actually landed (a pre-existing tenant
	// row with the same slug but a different id would silently break the
	// downstream harnesses, so surface it loudly rather than producing
	// payloads keyed on an unexpected id).
	expectedID := map[string]string{fleet.PlatformTenantSlug: fleet.PlatformTenantID}
	for _, t := range fleet.All() {
		expectedID[t.Slug] = t.ID
	}
	for slug, want := range expectedID {
		var got string
		if err := pool.QueryRow(ctx, `SELECT id::text FROM tenants WHERE slug = $1`, slug).Scan(&got); err != nil {
			return fmt.Errorf("verify tenant %s: %w", slug, err)
		}
		if got != want {
			return fmt.Errorf("tenant %s has id %s but the pipeline expects %s; reset the database (drop the seeded rows) and rerun the seed", slug, got, want)
		}
	}

	logf("bootstrap: platform_admin granted to operator %s; %d canonical tenants + MSP pinned", operatorID, len(fleet.All()))
	return nil
}

// openSeedPool connects as the owning login role (no SET SESSION ROLE):
// the bootstrap is an administrative, one-time provisioning step that
// inserts platform-scoped rows (roles, the operator user, the MSP),
// which is the DBA seam, not the per-request app seam. The PG_* env
// matches the control plane and the usage/anomalies harnesses.
func openSeedPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		seedEnvOr("PG_HOST", "localhost"), seedEnvOr("PG_PORT", "5432"),
		seedEnvOr("PG_USER", "sng"), seedEnvOr("PG_PASSWORD", "sng"),
		seedEnvOr("PG_DATABASE", "sng"), seedEnvOr("PG_SSLMODE", "disable"),
	)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func seedEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
