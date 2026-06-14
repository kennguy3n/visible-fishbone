// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// stubCoverageSource is a handler.ThreatFeedCoverageSource double that
// returns a canned coverage view and records the instant it was asked
// for.
type stubCoverageSource struct {
	cov    ai.FeedCoverage
	gotNow time.Time
}

func (s *stubCoverageSource) Coverage(now time.Time) ai.FeedCoverage {
	s.gotNow = now
	return s.cov
}

func threatFeedMux(src handler.ThreatFeedCoverageSource, authz handler.PlatformAuthorizer) *http.ServeMux {
	h := handler.NewThreatFeedHandler(src, authz)
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func sampleCoverage() ai.FeedCoverage {
	at := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	return ai.FeedCoverage{
		GeneratedAt: at,
		Feeds: []ai.FeedHealth{
			{
				Name:          "misp",
				Stale:         false,
				LastSuccessAt: at.Add(-10 * time.Minute),
				LastRunAt:     at.Add(-10 * time.Minute),
				Threshold:     3 * time.Hour,
				Runs:          12,
				Errors:        1,
			},
			{Name: "never", Stale: true, Threshold: 3 * time.Hour},
		},
		Store: ai.IOCCounts{Domains: 3, IPs: 2, Total: 5},
		BySource: map[string]ai.IOCCounts{
			"misp": {Domains: 3, Total: 3},
			"otx":  {IPs: 2, Total: 2},
		},
	}
}

func TestThreatFeedHandler_Coverage_Unauthenticated(t *testing.T) {
	t.Parallel()
	mux := threatFeedMux(&stubCoverageSource{cov: sampleCoverage()}, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	// No WithUserIDForTest -> uuid.Nil identity -> 401.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds/coverage", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestThreatFeedHandler_Coverage_Forbidden(t *testing.T) {
	t.Parallel()
	mux := threatFeedMux(&stubCoverageSource{cov: sampleCoverage()}, platformAuthz{allow: false})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds/coverage", nil)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestThreatFeedHandler_Coverage_OK(t *testing.T) {
	t.Parallel()
	src := &stubCoverageSource{cov: sampleCoverage()}
	mux := threatFeedMux(src, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds/coverage", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var body handler.FeedCoverageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(body.Feeds))
	}
	if body.Feeds[0].Name != "misp" || body.Feeds[0].ThresholdSeconds != 10800 {
		t.Errorf("feed[0] = %+v, want misp/10800s", body.Feeds[0])
	}
	if !body.Feeds[1].Stale || body.Feeds[1].LastSuccessAt != "" {
		t.Errorf("never feed should be stale with empty last_success_at, got %+v", body.Feeds[1])
	}
	if body.Store.Total != 5 {
		t.Errorf("store total = %d, want 5", body.Store.Total)
	}
	// by_source must be sorted by source for deterministic output.
	if len(body.BySource) != 2 || body.BySource[0].Source != "misp" || body.BySource[1].Source != "otx" {
		t.Errorf("by_source = %+v, want [misp, otx] sorted", body.BySource)
	}
	if body.BySource[0].Counts.Domains != 3 {
		t.Errorf("misp domains = %d, want 3", body.BySource[0].Counts.Domains)
	}
}

func TestThreatFeedHandler_Coverage_NilAuthzUnregistered(t *testing.T) {
	t.Parallel()
	// A nil authorizer must leave the route unregistered (404), never
	// expose an unguarded surface.
	mux := threatFeedMux(&stubCoverageSource{cov: sampleCoverage()}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds/coverage", nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route must not be registered)", rec.Code)
	}
}
