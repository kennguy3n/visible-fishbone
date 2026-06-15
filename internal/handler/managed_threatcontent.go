package handler

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/threatfeed"
)

// permManagedThreatContentWrite gates the system-scoped manual refresh
// trigger. Managed threat content is platform-global (one curated
// bundle for the whole fleet), so producing it is a platform operation:
// only a platform-scoped grant (platform_admin's wildcard) satisfies
// it, not a tenant/MSP grant. Defined here so this change does not edit
// shared rbac code; the rbac evaluator treats an unknown permission as
// satisfiable only by the platform wildcard.
const permManagedThreatContentWrite = "threatcontent:write"

// managedContentStaleAfter is the age past a feed's last successful
// ingest beyond which the posture reports it stale. It is several times
// the default hourly refresh cadence so a single missed refresh does
// not flap the status, while a genuinely stuck feed surfaces clearly.
const managedContentStaleAfter = 6 * time.Hour

// ManagedThreatContentStore is the read surface the posture endpoint
// needs. It is the read subset of repository.ThreatFeedRepository, so
// both the postgres and in-memory implementations satisfy it; kept
// narrow so tests can stub it without a database.
//
// Posture is read from the REPOSITORY, not from the producer's
// in-memory state, deliberately: the API is served by any replica but
// ingestion runs only on the elected leader, so only the persisted
// bundle + ingest state are visible fleet-wide. Reading the repository
// makes the endpoint correct on every replica.
type ManagedThreatContentStore interface {
	ListSources(ctx context.Context) ([]repository.ThreatFeedSource, error)
	ListIngestState(ctx context.Context) ([]repository.ThreatFeedIngestState, error)
	LatestBundle(ctx context.Context) (*repository.ThreatFeedBundle, error)
}

// ManagedThreatContentRefresher is the producer seam the manual-refresh
// trigger drives. Implemented by *threatfeed.Engine. Optional: without
// it (and an authorizer) the refresh route is not registered.
type ManagedThreatContentRefresher interface {
	RefreshOnce(ctx context.Context) (threatfeed.RefreshResult, error)
	Enabled() bool
}

// ManagedThreatContentHandler exposes the no-ops managed threat-content
// surface: a tenant-scoped read of the managed content a tenant
// receives (the same fleet-wide curated bundle, by design) and a
// system-scoped manual refresh trigger for operators.
//
// It is intentionally distinct from ThreatFeedHandler, which serves the
// operator-configured ai feed-coverage view. This handler is the
// managed (threatfeed) engine's surface.
type ManagedThreatContentHandler struct {
	store     ManagedThreatContentStore
	refresher ManagedThreatContentRefresher
	authz     PlatformAuthorizer
}

// NewManagedThreatContentHandler wires the handler. A nil store leaves
// every route unregistered; the refresh route additionally requires a
// refresher and an authorizer so it is never exposed unguarded.
func NewManagedThreatContentHandler(store ManagedThreatContentStore, refresher ManagedThreatContentRefresher, authz PlatformAuthorizer) *ManagedThreatContentHandler {
	return &ManagedThreatContentHandler{store: store, refresher: refresher, authz: authz}
}

// Register attaches the managed threat-content routes.
func (h *ManagedThreatContentHandler) Register(mux *http.ServeMux) {
	if h.store == nil {
		return
	}
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/threat-content/posture", h.posture)
	if h.refresher != nil && h.authz != nil {
		mux.HandleFunc("POST /api/v1/threat-content/refresh", h.refresh)
	}
}

// requirePlatform gates the system-scoped refresh route. Mirrors
// PoPHandler.requirePlatform.
func (h *ManagedThreatContentHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"system-scoped managed threat-content routes require an authenticated user identity")
		return false
	}
	allowed, err := h.authz.AuthorizePlatform(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate platform authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"credentials do not authorise managed threat-content operations")
		return false
	}
	return true
}

// --- response shapes ---

// ManagedBundleSummary is the JSON projection of the latest persisted
// bundle's metadata (never the indicator payload, which is large and
// signed for the data plane).
type ManagedBundleSummary struct {
	Serial         int64          `json:"serial"`
	SchemaVersion  int            `json:"schema_version"`
	GeneratedAt    string         `json:"generated_at"`
	KeyID          string         `json:"key_id"`
	Algorithm      string         `json:"algorithm"`
	IndicatorCount int64          `json:"indicator_count"`
	SizeBytes      int64          `json:"size_bytes"`
	Digest         string         `json:"digest"`
	CountsByType   map[string]int `json:"counts_by_type"`
}

// ManagedSourceStatus is the per-feed health row in the posture.
type ManagedSourceStatus struct {
	Name                string  `json:"name"`
	DisplayName         string  `json:"display_name"`
	Kind                string  `json:"kind"`
	Weight              float64 `json:"weight"`
	Enabled             bool    `json:"enabled"`
	IndicatorCount      int64   `json:"indicator_count"`
	LastSuccessAt       string  `json:"last_success_at,omitempty"`
	LastAttemptAt       string  `json:"last_attempt_at,omitempty"`
	LastError           string  `json:"last_error,omitempty"`
	ConsecutiveFailures int64   `json:"consecutive_failures"`
	Stale               bool    `json:"stale"`
}

// ManagedThreatContentPostureResponse is the read-only managed-content
// posture a tenant receives.
type ManagedThreatContentPostureResponse struct {
	// Enabled reflects the kill switch (true = managed content active).
	Enabled bool `json:"enabled"`
	// GeneratedAt is when this view was assembled.
	GeneratedAt string `json:"generated_at"`
	// Bundle is the latest distributed bundle's metadata, or null if
	// none has been produced yet.
	Bundle *ManagedBundleSummary `json:"bundle"`
	// Sources is the per-feed health, sorted by name.
	Sources []ManagedSourceStatus `json:"sources"`
}

// ManagedThreatContentRefreshResponse is the result of a manual refresh.
type ManagedThreatContentRefreshResponse struct {
	Skipped    bool                       `json:"skipped"`
	Unchanged  bool                       `json:"unchanged"`
	Serial     int64                      `json:"serial"`
	Indicators int                        `json:"indicators"`
	Published  bool                       `json:"published"`
	Sources    []ManagedRefreshSourceStat `json:"sources"`
}

// ManagedRefreshSourceStat is the per-feed outcome of a manual refresh.
type ManagedRefreshSourceStat struct {
	Source      string `json:"source"`
	Indicators  int    `json:"indicators"`
	NotModified bool   `json:"not_modified,omitempty"`
	UsedCache   bool   `json:"used_cache,omitempty"`
	// Disabled is true when the source is switched off in the registry, so
	// it was skipped this cycle. Surfacing it keeps a disabled feed (which
	// reports indicators=0 and no error) distinguishable from one that ran
	// but produced nothing.
	Disabled bool   `json:"disabled,omitempty"`
	Error    string `json:"error,omitempty"`
}

// posture returns the managed threat content the tenant receives. The
// content is fleet-wide (identical for every tenant) by design — this
// is the no-ops managed model — so the route is tenant-scoped only for
// access control, not because the content differs per tenant.
func (h *ManagedThreatContentHandler) posture(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sources, err := h.store.ListSources(ctx)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	states, err := h.store.ListIngestState(ctx)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	latest, err := h.store.LatestBundle(ctx)
	var bundle *ManagedBundleSummary
	switch {
	case err == nil:
		bundle = toManagedBundleSummary(latest)
	case errors.Is(err, repository.ErrNotFound):
		bundle = nil // no bundle produced yet
	default:
		WriteRepositoryError(w, err)
		return
	}

	now := time.Now()
	stateByName := make(map[string]repository.ThreatFeedIngestState, len(states))
	for _, st := range states {
		stateByName[st.SourceName] = st
	}

	out := make([]ManagedSourceStatus, 0, len(sources))
	for _, src := range sources {
		row := ManagedSourceStatus{
			Name:        src.Name,
			DisplayName: src.DisplayName,
			Kind:        src.Kind,
			Weight:      src.Weight,
			Enabled:     src.Enabled,
		}
		if st, ok := stateByName[src.Name]; ok {
			row.IndicatorCount = st.IndicatorCount
			row.LastError = st.LastError
			row.ConsecutiveFailures = st.ConsecutiveFailures
			if !st.LastSuccessAt.IsZero() {
				row.LastSuccessAt = st.LastSuccessAt.Format(rfc3339Nano)
			}
			if !st.LastAttemptAt.IsZero() {
				row.LastAttemptAt = st.LastAttemptAt.Format(rfc3339Nano)
			}
			row.Stale = isManagedSourceStale(st, now)
		} else {
			row.Stale = true // never ingested
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	enabled := true
	if h.refresher != nil {
		enabled = h.refresher.Enabled()
	}

	WriteJSON(w, http.StatusOK, ManagedThreatContentPostureResponse{
		Enabled:     enabled,
		GeneratedAt: now.Format(rfc3339Nano),
		Bundle:      bundle,
		Sources:     out,
	})
}

// refresh triggers one ingestion cycle on demand. System-scoped: it
// produces fleet-wide content, so it requires threatcontent:write at
// the platform level. Returns 409 when the kill switch is off.
func (h *ManagedThreatContentHandler) refresh(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permManagedThreatContentWrite) {
		return
	}
	if !h.refresher.Enabled() {
		WriteError(w, http.StatusConflict, "managed_content_disabled",
			"managed threat-content ingestion is disabled by the kill switch")
		return
	}
	res, err := h.refresher.RefreshOnce(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "refresh_failed",
			"managed threat-content refresh failed")
		return
	}

	sources := make([]ManagedRefreshSourceStat, 0, len(res.Sources))
	for _, s := range res.Sources {
		sources = append(sources, ManagedRefreshSourceStat{
			Source:      s.Source,
			Indicators:  s.Indicators,
			NotModified: s.NotModified,
			UsedCache:   s.UsedCache,
			Disabled:    s.Disabled,
			Error:       s.Err,
		})
	}
	WriteJSON(w, http.StatusOK, ManagedThreatContentRefreshResponse{
		Skipped:    res.Skipped,
		Unchanged:  res.Unchanged,
		Serial:     res.Serial,
		Indicators: res.Indicators,
		Published:  res.Published,
		Sources:    sources,
	})
}

func toManagedBundleSummary(b *repository.ThreatFeedBundle) *ManagedBundleSummary {
	if b == nil {
		return nil
	}
	counts := b.CountsByType
	if counts == nil {
		counts = map[string]int{}
	}
	return &ManagedBundleSummary{
		Serial:         b.Serial,
		SchemaVersion:  b.SchemaVersion,
		GeneratedAt:    b.GeneratedAt.Format(rfc3339Nano),
		KeyID:          b.KeyID,
		Algorithm:      b.Algorithm,
		IndicatorCount: b.IndicatorCount,
		SizeBytes:      b.SizeBytes,
		Digest:         b.Digest,
		CountsByType:   counts,
	}
}

// isManagedSourceStale reports whether a feed's ingest state indicates
// it is not delivering fresh content: it has never succeeded, is
// currently failing, or its last success is older than the staleness
// window.
func isManagedSourceStale(st repository.ThreatFeedIngestState, now time.Time) bool {
	if st.ConsecutiveFailures > 0 {
		return true
	}
	if st.LastSuccessAt.IsZero() {
		return true
	}
	return now.Sub(st.LastSuccessAt) > managedContentStaleAfter
}
