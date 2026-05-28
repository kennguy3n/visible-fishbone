// appdb.go exposes the REST surface for the Traffic Classification
// engine. Two route groups:
//
//   - Tenant-scoped (/api/v1/tenants/{tenant_id}/app-registry…)
//     for operators of a tenant who want to see the effective
//     classification and install per-tenant overrides.
//   - Admin (/api/v1/admin/app-registry…) for SNG operators who
//     curate the global catalog and trigger the vendor-endpoint
//     sync job.
//
// Both groups inherit the router's auth chain; admin endpoints have
// no extra middleware today because the operator API uses a single
// trust boundary (the SNG control-plane API key). When an
// admin-vs-tenant RBAC distinction lands, the only change needed is
// wrapping the admin routes here.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/appdb"
)

// TelemetryClassQuerier is the read-side dependency for the
// /app-registry/stats endpoint. The production wiring passes the
// ClickHouse writer; tests can pass a stub.
type TelemetryClassQuerier interface {
	QueryTrafficClassDistribution(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]TrafficClassStat, error)
}

// TrafficClassStat mirrors clickhouse.TrafficClassCount but lives
// in the handler package so the handler does not import the
// clickhouse package directly (keeps the handler dependency tree
// flat).
type TrafficClassStat struct {
	Class  string `json:"class"`
	Events uint64 `json:"events"`
	Bytes  uint64 `json:"bytes"`
}

// AppRegistrySyncer is the write-side dependency for the
// `POST /admin/app-registry/sync` endpoint. The production wiring
// passes the *appdb.Syncer; tests can pass a fake.
type AppRegistrySyncer interface {
	SyncAll(ctx context.Context) ([]appdb.SyncResult, error)
}

// AppRegistryHandler hosts the traffic-classification REST surface.
//
// `stats` is held behind an atomic.Pointer because production
// wiring may attach the ClickHouse-backed querier *after*
// NewAppRegistryHandler returns (the clickhouse writer is built
// inside startTelemetry, which runs after the router is
// constructed). The atomic load on the request path costs less
// than a mutex and avoids a data race when SetStats races with
// an in-flight request during boot.
type AppRegistryHandler struct {
	svc    *appdb.Service
	stats  atomic.Pointer[telemetryQuerierBox]
	syncer AppRegistrySyncer
}

// telemetryQuerierBox wraps the interface so atomic.Pointer can
// hold a typed value (atomic.Pointer is parameterised by struct
// type only — it does not accept interface types directly).
type telemetryQuerierBox struct {
	q TelemetryClassQuerier
}

// NewAppRegistryHandler wires the handler. stats / syncer may be
// nil when their respective subsystems are disabled — the handler
// responds 503 on the matching endpoints in that case. Stats can
// also be attached later via SetStats once the ClickHouse writer
// is available.
func NewAppRegistryHandler(svc *appdb.Service, stats TelemetryClassQuerier, syncer AppRegistrySyncer) *AppRegistryHandler {
	h := &AppRegistryHandler{svc: svc, syncer: syncer}
	if stats != nil {
		h.stats.Store(&telemetryQuerierBox{q: stats})
	}
	return h
}

// SetStats attaches (or replaces) the telemetry class querier.
// Safe to call concurrently with request serving. Pass nil to
// detach (the stats endpoint will then 503).
func (h *AppRegistryHandler) SetStats(stats TelemetryClassQuerier) {
	if h == nil {
		return
	}
	if stats == nil {
		h.stats.Store(nil)
		return
	}
	h.stats.Store(&telemetryQuerierBox{q: stats})
}

// currentStats returns the attached querier or nil. Reads are
// lock-free.
func (h *AppRegistryHandler) currentStats() TelemetryClassQuerier {
	box := h.stats.Load()
	if box == nil {
		return nil
	}
	return box.q
}

// Register attaches routes.
func (h *AppRegistryHandler) Register(mux *http.ServeMux) {
	if h == nil || h.svc == nil {
		return
	}
	// Tenant-scoped — RequireTenant applied by MountTenantScoped.
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/app-registry", h.listEffective)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/app-registry/overrides", h.createOverride)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/app-registry/overrides", h.listOverrides)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/app-registry/overrides/{id}", h.deleteOverride)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/app-registry/stats", h.stats_handler)

	// Admin — global catalog management. No path tenant binding;
	// the router's auth chain handles authentication.
	mux.HandleFunc("GET /api/v1/admin/app-registry", h.adminListApps)
	mux.HandleFunc("POST /api/v1/admin/app-registry", h.adminCreateApp)
	mux.HandleFunc("PUT /api/v1/admin/app-registry/{id}", h.adminUpdateApp)
	mux.HandleFunc("DELETE /api/v1/admin/app-registry/{id}", h.adminDeleteApp)
	mux.HandleFunc("POST /api/v1/admin/app-registry/sync", h.adminSync)
}

// --- Request / response DTOs ---------------------------------------------

// AppRegistryRequest is the JSON body for admin create / update.
type AppRegistryRequest struct {
	Name         string   `json:"name"`
	Vendor       string   `json:"vendor,omitempty"`
	TrafficClass string   `json:"traffic_class"`
	Scope        string   `json:"scope"`
	Regions      []string `json:"regions,omitempty"`
	Domains      []string `json:"domains"`
	IPRanges     []string `json:"ip_ranges,omitempty"`
	CertPins     []string `json:"cert_pins,omitempty"`
	MetadataURL  string   `json:"metadata_url,omitempty"`
	Category     string   `json:"category,omitempty"`
	IsSystem     *bool    `json:"is_system,omitempty"`
}

// AppRegistryResponse is the JSON projection of repository.AppRegistry.
type AppRegistryResponse struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Vendor       string   `json:"vendor,omitempty"`
	TrafficClass string   `json:"traffic_class"`
	Scope        string   `json:"scope"`
	Regions      []string `json:"regions,omitempty"`
	Domains      []string `json:"domains"`
	IPRanges     []string `json:"ip_ranges,omitempty"`
	CertPins     []string `json:"cert_pins,omitempty"`
	MetadataURL  string   `json:"metadata_url,omitempty"`
	Category     string   `json:"category,omitempty"`
	IsSystem     bool     `json:"is_system"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// OverrideRequest is the JSON body for tenant override creation.
type OverrideRequest struct {
	AppID                string    `json:"app_id,omitempty"`
	CustomDomains        []string  `json:"custom_domains,omitempty"`
	TrafficClassOverride string    `json:"traffic_class_override"`
	Reason               string    `json:"reason,omitempty"`
	ExpiresAt            *string   `json:"expires_at,omitempty"` // RFC3339
}

// OverrideResponse is the JSON projection of repository.AppRegistryOverride.
type OverrideResponse struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	AppID                string   `json:"app_id,omitempty"`
	CustomDomains        []string `json:"custom_domains,omitempty"`
	TrafficClassOverride string   `json:"traffic_class_override"`
	Reason               string   `json:"reason,omitempty"`
	ExpiresAt            string   `json:"expires_at,omitempty"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
}

// EffectiveAppResponse is the merged view (global + tenant
// override) the tenant-scoped GET returns.
type EffectiveAppResponse struct {
	App               AppRegistryResponse `json:"app"`
	EffectiveClass    string              `json:"effective_class"`
	Source            string              `json:"source"`
	OverrideID        string              `json:"override_id,omitempty"`
	OverrideExpiresAt string              `json:"override_expires_at,omitempty"`
	OverrideReason    string              `json:"override_reason,omitempty"`
}

func toAppResponse(a repository.AppRegistry) AppRegistryResponse {
	ipRanges := make([]string, 0, len(a.IPRanges))
	for _, p := range a.IPRanges {
		ipRanges = append(ipRanges, p.String())
	}
	return AppRegistryResponse{
		ID:           a.ID.String(),
		Name:         a.Name,
		Vendor:       a.Vendor,
		TrafficClass: string(a.TrafficClass),
		Scope:        string(a.Scope),
		Regions:      a.Regions,
		Domains:      a.Domains,
		IPRanges:     ipRanges,
		CertPins:     a.CertPins,
		MetadataURL:  a.MetadataURL,
		Category:     a.Category,
		IsSystem:     a.IsSystem,
		CreatedAt:    a.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:    a.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func toOverrideResponse(o repository.AppRegistryOverride) OverrideResponse {
	out := OverrideResponse{
		ID:                   o.ID.String(),
		TenantID:             o.TenantID.String(),
		CustomDomains:        o.CustomDomains,
		TrafficClassOverride: string(o.TrafficClassOverride),
		Reason:               o.Reason,
		CreatedAt:            o.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:            o.UpdatedAt.Format(time.RFC3339Nano),
	}
	if o.AppID != nil {
		out.AppID = o.AppID.String()
	}
	if o.ExpiresAt != nil {
		out.ExpiresAt = o.ExpiresAt.Format(time.RFC3339Nano)
	}
	return out
}

func toEffectiveResponse(e appdb.EffectiveApp) EffectiveAppResponse {
	out := EffectiveAppResponse{
		App:            toAppResponse(e.App),
		EffectiveClass: string(e.EffectiveClass),
		Source:         e.Source,
		OverrideReason: e.OverrideReason,
	}
	if e.OverrideID != nil {
		out.OverrideID = e.OverrideID.String()
	}
	if e.OverrideExpiresAt != nil {
		out.OverrideExpiresAt = e.OverrideExpiresAt.Format(time.RFC3339Nano)
	}
	return out
}

// --- Tenant-scoped handlers ----------------------------------------------

func (h *AppRegistryHandler) listEffective(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	eff, err := h.svc.ListEffective(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]EffectiveAppResponse, 0, len(eff))
	for _, e := range eff {
		items = append(items, toEffectiveResponse(e))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (h *AppRegistryHandler) createOverride(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req OverrideRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	cls := repository.TrafficClass(req.TrafficClassOverride)
	if !cls.IsValid() {
		WriteError(w, http.StatusBadRequest, "invalid_class", "traffic_class_override is invalid")
		return
	}
	ov := repository.AppRegistryOverride{
		TrafficClassOverride: cls,
		Reason:               req.Reason,
	}
	if req.AppID != "" {
		id, err := uuid.Parse(req.AppID)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_app_id", "app_id must be a UUID")
			return
		}
		ov.AppID = &id
	}
	ov.CustomDomains = req.CustomDomains
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339Nano, *req.ExpiresAt)
		if err != nil {
			// Accept the RFC3339 short form too.
			t, err = time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				WriteError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be RFC3339")
				return
			}
		}
		ov.ExpiresAt = &t
	}
	created, err := h.svc.CreateOverride(r.Context(), tenantID, actorFromCtx(r), ov)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toOverrideResponse(created))
}

func (h *AppRegistryHandler) listOverrides(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.ListOverrides(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]OverrideResponse, 0, len(res.Items))
	for _, ov := range res.Items {
		items = append(items, toOverrideResponse(ov))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *AppRegistryHandler) deleteOverride(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteOverride(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppRegistryHandler) stats_handler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	stats := h.currentStats()
	if stats == nil {
		WriteError(w, http.StatusServiceUnavailable, "telemetry_disabled", "traffic-class stats require ClickHouse telemetry")
		return
	}
	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_since", "since must be RFC3339")
			return
		}
		since = t
	}
	if v := r.URL.Query().Get("window_hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			WriteError(w, http.StatusBadRequest, "invalid_window", "window_hours must be a positive integer")
			return
		}
		since = time.Now().UTC().Add(-time.Duration(n) * time.Hour)
	}
	rows, err := stats.QueryTrafficClassDistribution(r.Context(), tenantID, since)
	if err != nil {
		WriteError(w, http.StatusBadGateway, "telemetry_query", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"since": since.Format(time.RFC3339),
		"items": rows,
	})
}

// --- Admin handlers ------------------------------------------------------

func (h *AppRegistryHandler) adminListApps(w http.ResponseWriter, r *http.Request) {
	filter := repository.AppRegistryFilter{
		TrafficClass: repository.TrafficClass(r.URL.Query().Get("traffic_class")),
		Scope:        repository.AppRegistryScope(r.URL.Query().Get("scope")),
		Region:       r.URL.Query().Get("region"),
		Category:     r.URL.Query().Get("category"),
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.ListApps(r.Context(), filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]AppRegistryResponse, 0, len(res.Items))
	for _, a := range res.Items {
		items = append(items, toAppResponse(a))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *AppRegistryHandler) adminCreateApp(w http.ResponseWriter, r *http.Request) {
	var req AppRegistryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	app, err := parseAppRequest(req, repository.AppRegistry{})
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	created, err := h.svc.CreateApp(r.Context(), app)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toAppResponse(created))
}

func (h *AppRegistryHandler) adminUpdateApp(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	existing, err := h.svc.GetApp(r.Context(), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	var req AppRegistryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	merged, err := parseAppRequest(req, existing)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	merged.ID = id
	updated, err := h.svc.UpdateApp(r.Context(), merged)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAppResponse(updated))
}

func (h *AppRegistryHandler) adminDeleteApp(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteApp(r.Context(), id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppRegistryHandler) adminSync(w http.ResponseWriter, r *http.Request) {
	if h.syncer == nil {
		WriteError(w, http.StatusServiceUnavailable, "sync_disabled", "vendor sync not configured")
		return
	}
	results, err := h.syncer.SyncAll(r.Context())
	if err != nil {
		WriteError(w, http.StatusBadGateway, "sync_error", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"results": results,
	})
}

// parseAppRequest merges req into base. Used by both create
// (base = zero) and update (base = existing row). Returns the
// resulting AppRegistry value or an error describing the first
// validation problem.
func parseAppRequest(req AppRegistryRequest, base repository.AppRegistry) (repository.AppRegistry, error) {
	out := base
	if req.Name != "" {
		out.Name = req.Name
	}
	if req.Vendor != "" {
		out.Vendor = req.Vendor
	}
	if req.TrafficClass != "" {
		out.TrafficClass = repository.TrafficClass(req.TrafficClass)
	}
	if !out.TrafficClass.IsValid() {
		return out, errors.New("traffic_class is required and must be valid")
	}
	if req.Scope != "" {
		out.Scope = repository.AppRegistryScope(req.Scope)
	}
	if !out.Scope.IsValid() {
		return out, errors.New("scope is required and must be 'global' or 'regional'")
	}
	if req.Regions != nil {
		out.Regions = req.Regions
	}
	if out.Scope == repository.AppRegistryScopeRegional && len(out.Regions) == 0 {
		return out, errors.New("regions must be non-empty for regional scope")
	}
	if req.Domains != nil {
		out.Domains = req.Domains
	}
	if len(out.Domains) == 0 {
		return out, errors.New("domains must be non-empty")
	}
	if req.IPRanges != nil {
		parsed := make([]netip.Prefix, 0, len(req.IPRanges))
		for _, raw := range req.IPRanges {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return out, errors.New("invalid ip_range: " + raw)
			}
			parsed = append(parsed, p)
		}
		out.IPRanges = parsed
	}
	if req.CertPins != nil {
		out.CertPins = req.CertPins
	}
	if req.MetadataURL != "" {
		out.MetadataURL = req.MetadataURL
	}
	if req.Category != "" {
		out.Category = req.Category
	}
	if req.IsSystem != nil {
		out.IsSystem = *req.IsSystem
	} else if base.ID == uuid.Nil {
		// Operator-created entries default to non-system so the
		// auto-sync job leaves them alone.
		out.IsSystem = false
	}
	return out, nil
}
