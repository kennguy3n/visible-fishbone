package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/threatfeed"
)

// stubThreatContentStore is a ManagedThreatContentStore double.
type stubThreatContentStore struct {
	sources   []repository.ThreatFeedSource
	states    []repository.ThreatFeedIngestState
	bundle    *repository.ThreatFeedBundle
	bundleErr error
	listErr   error
}

func (s *stubThreatContentStore) ListSources(context.Context) ([]repository.ThreatFeedSource, error) {
	return s.sources, s.listErr
}

func (s *stubThreatContentStore) ListIngestState(context.Context) ([]repository.ThreatFeedIngestState, error) {
	return s.states, nil
}

func (s *stubThreatContentStore) LatestBundle(context.Context) (*repository.ThreatFeedBundle, error) {
	if s.bundleErr != nil {
		return nil, s.bundleErr
	}
	if s.bundle == nil {
		return nil, repository.ErrNotFound
	}
	return s.bundle, nil
}

// stubRefresher is a ManagedThreatContentRefresher double.
type stubRefresher struct {
	enabled bool
	result  threatfeed.RefreshResult
	err     error
	calls   int
}

func (r *stubRefresher) RefreshOnce(context.Context) (threatfeed.RefreshResult, error) {
	r.calls++
	return r.result, r.err
}

func (r *stubRefresher) Enabled() bool { return r.enabled }

func managedMux(store handler.ManagedThreatContentStore, refresher handler.ManagedThreatContentRefresher, authz handler.PlatformAuthorizer) *http.ServeMux {
	h := handler.NewManagedThreatContentHandler(store, refresher, authz)
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func posturePath() string {
	return "/api/v1/tenants/" + uuid.New().String() + "/threat-content/posture"
}

func TestManagedThreatContent_PostureWithBundle(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	store := &stubThreatContentStore{
		sources: []repository.ThreatFeedSource{
			{Name: "feedB", DisplayName: "B", Kind: "ip", Weight: 0.9, Enabled: true},
			{Name: "feedA", DisplayName: "A", Kind: "url", Weight: 0.8, Enabled: true},
		},
		states: []repository.ThreatFeedIngestState{
			{SourceName: "feedA", LastSuccessAt: now, LastAttemptAt: now, IndicatorCount: 5},
		},
		bundle: &repository.ThreatFeedBundle{
			Serial: 42, SchemaVersion: 1, GeneratedAt: now, KeyID: "k", Algorithm: "ed25519",
			IndicatorCount: 5, SizeBytes: 100, Digest: "abc", CountsByType: map[string]int{"ip": 3, "url": 2},
		},
	}
	mux := managedMux(store, &stubRefresher{enabled: true}, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp handler.ManagedThreatContentPostureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled {
		t.Fatal("Enabled should reflect refresher.Enabled()=true")
	}
	if resp.Bundle == nil || resp.Bundle.Serial != 42 {
		t.Fatalf("bundle = %+v", resp.Bundle)
	}
	if len(resp.Sources) != 2 || resp.Sources[0].Name != "feedA" || resp.Sources[1].Name != "feedB" {
		t.Fatalf("sources not sorted by name: %+v", resp.Sources)
	}
	// feedA ingested successfully and recently -> not stale.
	if resp.Sources[0].Stale {
		t.Fatal("feedA should not be stale")
	}
	// feedB has no ingest state -> stale (never ingested).
	if !resp.Sources[1].Stale {
		t.Fatal("feedB never ingested should be stale")
	}
}

func TestManagedThreatContent_PostureNoBundle(t *testing.T) {
	t.Parallel()
	store := &stubThreatContentStore{} // LatestBundle -> ErrNotFound
	mux := managedMux(store, &stubRefresher{enabled: true}, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp handler.ManagedThreatContentPostureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Bundle != nil {
		t.Fatalf("bundle should be null before first production, got %+v", resp.Bundle)
	}
}

func TestManagedThreatContent_PostureEnabledReflectsKillSwitch(t *testing.T) {
	t.Parallel()
	store := &stubThreatContentStore{}
	mux := managedMux(store, &stubRefresher{enabled: false}, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	var resp handler.ManagedThreatContentPostureResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Enabled {
		t.Fatal("Enabled should be false when kill switch off")
	}
}

func TestManagedThreatContent_PostureNilRefresherDefaultsEnabled(t *testing.T) {
	t.Parallel()
	store := &stubThreatContentStore{}
	mux := managedMux(store, nil, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp handler.ManagedThreatContentPostureResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Enabled {
		t.Fatal("Enabled should default true when no refresher is wired")
	}
}

func TestManagedThreatContent_PostureStoreError(t *testing.T) {
	t.Parallel()
	store := &stubThreatContentStore{listErr: errors.New("db down")}
	mux := managedMux(store, &stubRefresher{enabled: true}, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestManagedThreatContent_RefreshHappyPath(t *testing.T) {
	t.Parallel()
	ref := &stubRefresher{
		enabled: true,
		result: threatfeed.RefreshResult{
			Serial: 7, Indicators: 3, Published: true,
			Sources: []threatfeed.SourceStat{{Source: "feedA", Indicators: 3}},
		},
	}
	mux := managedMux(&stubThreatContentStore{}, ref, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/threat-content/refresh", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ref.calls != 1 {
		t.Fatalf("RefreshOnce called %d times, want 1", ref.calls)
	}
	var resp handler.ManagedThreatContentRefreshResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Serial != 7 || resp.Indicators != 3 || !resp.Published {
		t.Fatalf("resp = %+v", resp)
	}
	if len(resp.Sources) != 1 || resp.Sources[0].Source != "feedA" {
		t.Fatalf("sources = %+v", resp.Sources)
	}
}

func TestManagedThreatContent_RefreshDisabledConflict(t *testing.T) {
	t.Parallel()
	ref := &stubRefresher{enabled: false}
	mux := managedMux(&stubThreatContentStore{}, ref, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/threat-content/refresh", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if ref.calls != 0 {
		t.Fatal("disabled engine must not run a refresh")
	}
}

func TestManagedThreatContent_RefreshForbidden(t *testing.T) {
	t.Parallel()
	ref := &stubRefresher{enabled: true}
	mux := managedMux(&stubThreatContentStore{}, ref, platformAuthz{allow: false})

	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/threat-content/refresh", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ref.calls != 0 {
		t.Fatal("unauthorized caller must not trigger a refresh")
	}
}

func TestManagedThreatContent_RefreshUnauthenticated(t *testing.T) {
	t.Parallel()
	ref := &stubRefresher{enabled: true}
	mux := managedMux(&stubThreatContentStore{}, ref, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	// No authedReq -> no identity -> 401.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/threat-content/refresh", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestManagedThreatContent_RefreshRouteRequiresRefresherAndAuthz(t *testing.T) {
	t.Parallel()
	// Store present but no refresher/authz: refresh route is NOT
	// registered, so the posture route exists but refresh 404s.
	mux := managedMux(&stubThreatContentStore{}, nil, nil)

	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/threat-content/refresh", bytes.NewBufferString("{}")))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route unregistered)", rec.Code)
	}
}

func TestManagedThreatContent_NilStoreRegistersNothing(t *testing.T) {
	t.Parallel()
	mux := managedMux(nil, &stubRefresher{enabled: true}, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, posturePath(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no routes when store nil)", rec.Code)
	}
}
