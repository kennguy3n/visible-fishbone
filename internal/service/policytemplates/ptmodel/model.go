// Package ptmodel holds the persistence-facing data types for the
// policytemplates service. It is a deliberately dependency-free leaf
// package: it imports only the standard library and uuid, never the
// policy graph package. This lets repository implementations
// (internal/repository/{memory,postgres}) reference these types to
// satisfy policytemplates.Repository WITHOUT importing the
// policytemplates service package itself — which transitively depends
// on internal/service/policy and internal/middleware and would
// otherwise form an import cycle (middleware -> postgres -> ptmodel?
// no; middleware -> postgres -> policytemplates -> policy ->
// middleware). Keeping the DTOs here keeps that arrow from ever
// pointing back into the service layer.
package ptmodel

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CatalogRow is the persisted form of a catalog Template (migration
// 062's global policy_templates table). Primitive-typed so the
// persistence layer never depends on the catalog's typed vocabulary;
// the service maps between its Template type and CatalogRow.
type CatalogRow struct {
	ID          string
	Kind        string
	Industry    string // empty unless Kind == industry
	Regime      string // empty unless Kind == compliance
	Name        string
	Description string
	// Spec is the JSON-encoded Template.Spec.
	Spec json.RawMessage
	// ContentHash is the SHA-256 of the canonical Spec encoding,
	// letting UpsertCatalog skip a write when nothing changed.
	ContentHash string
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AppliedTemplate is a tenant's persisted baseline selection and the
// rendered Policy-Graph intent (migration 062's per-tenant
// tenant_policy_templates table). One row per tenant: a tenant has a
// single active baseline at a time.
type AppliedTemplate struct {
	TenantID uuid.UUID
	Industry string
	Country  string
	Regime   string
	// TemplateIDs are the catalog templates that composed the graph.
	TemplateIDs []string
	// GraphHash is the SHA-256 of Graph; the idempotency key.
	GraphHash string
	// Graph is the canonical rendered Policy-Graph intent.
	Graph json.RawMessage
	// Version is the renderer's GraphVersion at apply time.
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}
