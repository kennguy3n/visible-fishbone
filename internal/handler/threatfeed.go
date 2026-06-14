package handler

import (
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// Threat-feed observability permission. Feeds are platform-global
// (shared fleet-wide, not tenant-owned), so the read surface is
// platform-scoped — an MSP- or tenant-scoped grant does NOT satisfy
// it; platform_admin (wildcard) does. Mirrors pops:read.
const permThreatFeedsRead = "threatfeeds:read"

// ThreatFeedCoverageSource is the narrow read surface the handler
// needs: the live "what intel is live" view. Implemented by
// *ai.FeedManager; kept as an interface so tests can stub it without
// standing up a feed manager + store.
type ThreatFeedCoverageSource interface {
	Coverage(now time.Time) ai.FeedCoverage
}

// ThreatFeedHandler exposes the read-only threat-intel feed coverage
// surface so an operator can see, in one call, whether every feed is
// fresh and what each one is contributing to the shared indicator
// store right now.
type ThreatFeedHandler struct {
	cov   ThreatFeedCoverageSource
	authz PlatformAuthorizer
}

// NewThreatFeedHandler wires the handler. Either dependency may be
// nil: a nil source or a nil authorizer leaves the route unregistered
// (it 404s) — the feature is strictly opt-in and never weakens the
// platform gate.
func NewThreatFeedHandler(cov ThreatFeedCoverageSource, authz PlatformAuthorizer) *ThreatFeedHandler {
	return &ThreatFeedHandler{cov: cov, authz: authz}
}

// Register attaches the authenticated, platform-gated coverage route.
// Registered only when both the source and the authorizer are wired,
// so a deployment without a feed manager (or without RBAC) does not
// expose an unguarded or always-erroring endpoint.
func (h *ThreatFeedHandler) Register(mux *http.ServeMux) {
	if h.cov == nil || h.authz == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/threat-intel/feeds/coverage", h.coverage)
}

// requirePlatform gates the platform-scoped coverage route. Mirrors
// PoPHandler.requirePlatform.
func (h *ThreatFeedHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped threat-intel routes require an authenticated user identity")
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
			"credentials do not authorise platform-scoped threat-intel operations")
		return false
	}
	return true
}

// --- response shapes ---

// IOCCountsResponse is the JSON projection of ai.IOCCounts.
type IOCCountsResponse struct {
	Domains int `json:"domains"`
	IPs     int `json:"ips"`
	CIDRs   int `json:"cidrs"`
	URLs    int `json:"urls"`
	Hashes  int `json:"hashes"`
	JA3s    int `json:"ja3s"`
	Total   int `json:"total"`
}

func toIOCCountsResponse(c ai.IOCCounts) IOCCountsResponse {
	return IOCCountsResponse{
		Domains: c.Domains,
		IPs:     c.IPs,
		CIDRs:   c.CIDRs,
		URLs:    c.URLs,
		Hashes:  c.Hashes,
		JA3s:    c.JA3s,
		Total:   c.Total,
	}
}

// IPSRuleEfficacyResponse is the JSON projection of
// ai.IPSRuleEfficacy: the per-category Suricata-rule cardinality the
// live store compiles into the signed IPS rule bundle.
type IPSRuleEfficacyResponse struct {
	Total      int            `json:"total"`
	ByCategory map[string]int `json:"by_category"`
}

func toIPSRuleEfficacyResponse(e ai.IPSRuleEfficacy) IPSRuleEfficacyResponse {
	byCat := make(map[string]int, len(e.ByCategory))
	for _, cat := range policy.AllIPSRuleCategories() {
		byCat[string(cat)] = e.ByCategory[cat]
	}
	return IPSRuleEfficacyResponse{Total: e.Total, ByCategory: byCat}
}

// FeedHealthResponse is the JSON projection of ai.FeedHealth.
type FeedHealthResponse struct {
	Name             string `json:"name"`
	Stale            bool   `json:"stale"`
	LastSuccessAt    string `json:"last_success_at,omitempty"`
	LastRunAt        string `json:"last_run_at,omitempty"`
	ThresholdSeconds int64  `json:"threshold_seconds"`
	Runs             int64  `json:"runs"`
	Errors           int64  `json:"errors"`
}

// SourceCoverageResponse attributes live indicator cardinality to the
// source feed that contributed it.
type SourceCoverageResponse struct {
	Source string            `json:"source"`
	Counts IOCCountsResponse `json:"counts"`
}

// FeedCoverageResponse is the JSON projection of ai.FeedCoverage.
type FeedCoverageResponse struct {
	GeneratedAt string                   `json:"generated_at"`
	Feeds       []FeedHealthResponse     `json:"feeds"`
	Store       IOCCountsResponse        `json:"store"`
	BySource    []SourceCoverageResponse `json:"by_source"`
	IPSRules    IPSRuleEfficacyResponse  `json:"ips_rules"`
}

// coverage returns the live feed health + indicator-coverage view.
// Platform-scoped: feeds are global infrastructure shared fleet-wide,
// so it requires threatfeeds:read at the platform level.
func (h *ThreatFeedHandler) coverage(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permThreatFeedsRead) {
		return
	}
	cov := h.cov.Coverage(time.Now())

	feeds := make([]FeedHealthResponse, 0, len(cov.Feeds))
	for _, f := range cov.Feeds {
		fr := FeedHealthResponse{
			Name:             f.Name,
			Stale:            f.Stale,
			ThresholdSeconds: int64(f.Threshold / time.Second),
			Runs:             f.Runs,
			Errors:           f.Errors,
		}
		if !f.LastSuccessAt.IsZero() {
			fr.LastSuccessAt = f.LastSuccessAt.Format(rfc3339Nano)
		}
		if !f.LastRunAt.IsZero() {
			fr.LastRunAt = f.LastRunAt.Format(rfc3339Nano)
		}
		feeds = append(feeds, fr)
	}

	// Emit by_source as a stable, sorted slice rather than a map so
	// the response is byte-deterministic for caching / diffing.
	bySource := make([]SourceCoverageResponse, 0, len(cov.BySource))
	for src, counts := range cov.BySource {
		bySource = append(bySource, SourceCoverageResponse{
			Source: src,
			Counts: toIOCCountsResponse(counts),
		})
	}
	sort.Slice(bySource, func(i, j int) bool {
		return bySource[i].Source < bySource[j].Source
	})

	WriteJSON(w, http.StatusOK, FeedCoverageResponse{
		GeneratedAt: cov.GeneratedAt.Format(rfc3339Nano),
		Feeds:       feeds,
		Store:       toIOCCountsResponse(cov.Store),
		BySource:    bySource,
		IPSRules:    toIPSRuleEfficacyResponse(cov.IPSRules),
	})
}
