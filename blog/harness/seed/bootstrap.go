// bootstrap.go provisions the two pieces of state the API-driven seed
// run cannot create for itself, so `go run ./blog/harness/seed` is
// fully reproducible against a freshly-migrated database.
//
// 1. Platform RBAC grant. The seed and capture harnesses act as a
//    global platform operator (a JWT with roles:["platform_admin"] and
//    no tenant_id claim). The control plane authorises the
//    platform-scoped routes — POST/GET /api/v1/msps, the admin
//    cost-report, the global audit log — via the *database-backed* RBAC
//    store (rbac.Service.AuthorizePlatform reads user_roles), NOT the
//    JWT roles claim. A fresh database has no role grants, so those
//    routes return 403 platform_forbidden and the MSP onboarding step
//    (S1 evidence) fails. This is a genuine bootstrap chicken-and-egg:
//    you cannot grant yourself platform authority through an API that
//    already requires it. We therefore seed the operator user and its
//    platform_admin grant directly. RBAC enforcement is unchanged — the
//    operator is authorised through the same real grant a production
//    deployment would provision for its first platform admin.
//
// 2. Canonical fixture identities. The tenant create API deliberately
//    does not accept a client-supplied id (server-assigned UUIDs only),
//    but the capture/usage/anomalies harnesses, the committed payloads,
//    and the blog posts all reference four stable tenant UUIDs (and the
//    MSP UUID). Seeding those identity rows here keeps the whole
//    pipeline deterministic across reruns and fresh databases; every
//    business sub-resource (sites, devices, policies, DLP, …) is still
//    created through the real operator API by the rest of the harness.
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
)

// canonicalTenantID pins each scenario tenant's slug to the stable UUID
// the rest of the pipeline (capture/usage/anomalies harnesses, payloads,
// blog posts) references. Slugs, names, regions and tiers come from the
// single source of truth in scenarioTenants(); only the identity is
// pinned here.
var canonicalTenantID = map[string]string{
	"acme-retail":        "92112770-7c0a-410b-b0f4-09dde70e063a",
	"globex-health":      "3bd7bb7b-d48a-4569-8f97-46be31ae8e5a",
	"initech-financial":  "b6520bda-e7bb-4af9-9c53-7b0051eae65b",
	"umbrella-logistics": "0c8d2d9d-896d-45b1-8001-6a6776f832b9",
}

const (
	// canonicalMSPID is the stable MSP UUID the S1 payloads
	// (s1-msps.json, the msp_id on s1-tenants.json) reference. The
	// seed's ensureMSP() finds it by slug and reuses it.
	canonicalMSPID = "b47fb518-f336-4449-82b0-bd33a1f36833"
	// platformAdminRoleID is a fixed id for the platform_admin role so
	// reruns never create a duplicate grant target.
	platformAdminRoleID = "a0000000-0000-4000-8000-000000000001"
	// The platform tenant ("ShieldNet Platform") is the system tenant
	// that houses platform-scoped operators. It is pinned to a stable
	// UUID because GET /api/v1/tenants enumerates it alongside the four
	// managed tenants (S1 evidence: s1-tenants.json carries five rows).
	// The platform operator is homed here rather than inside a customer
	// tenant so a platform principal never pollutes a tenant's user set
	// and the isolation story stays clean.
	platformTenantID   = "f79e9245-24eb-4573-b9f9-7e5b34fd7056"
	platformTenantSlug = "platform"
	platformTenantName = "ShieldNet Platform"
	platformTenantTier = "enterprise"
)

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
		id, ok := canonicalTenantID[t.slug]
		if !ok {
			return fmt.Errorf("no canonical id pinned for tenant slug %q", t.slug)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenants (id, name, slug, status, region, tier)
			VALUES ($1::uuid, $2, $3, 'active', NULLIF($4, ''), $5)
			ON CONFLICT (slug) DO NOTHING`,
			id, t.name, t.slug, t.region, t.tier); err != nil {
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
		platformTenantID, platformTenantName, platformTenantSlug, platformTenantTier); err != nil {
		return fmt.Errorf("seed platform tenant: %w", err)
	}

	// 3. canonical MSP identity row; ensureMSP() reuses it by slug.
	if _, err := tx.Exec(ctx, `
		INSERT INTO msps (id, name, slug, status)
		VALUES ($1::uuid, 'Northwind Managed Security', 'northwind-msp', 'active')
		ON CONFLICT (id) DO NOTHING`, canonicalMSPID); err != nil {
		return fmt.Errorf("seed msp: %w", err)
	}

	// 4. operator user, homed in the platform tenant. users is
	// RLS-FORCEd, so set the tenant GUC for this statement exactly as
	// the control plane does before writing.
	homeID := platformTenantID
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
	auditTenantIDs := make([]string, 0, len(canonicalTenantID)+1)
	for _, id := range canonicalTenantID {
		auditTenantIDs = append(auditTenantIDs, id)
	}
	auditTenantIDs = append(auditTenantIDs, platformTenantID)
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
	expectedID := map[string]string{platformTenantSlug: platformTenantID}
	for slug, want := range canonicalTenantID {
		expectedID[slug] = want
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

	logf("bootstrap: platform_admin granted to operator %s; %d canonical tenants + MSP pinned", operatorID, len(canonicalTenantID))
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
