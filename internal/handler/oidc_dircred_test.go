package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// fakeDirCredStore is an in-memory identity.DirectoryCredentialStore for
// handler tests (the postgres RLS-scoped store is exercised elsewhere).
type fakeDirCredStore struct{ rows map[uuid.UUID][]byte }

func newFakeDirCredStore() *fakeDirCredStore {
	return &fakeDirCredStore{rows: map[uuid.UUID][]byte{}}
}

func (f *fakeDirCredStore) GetSealed(_ context.Context, _, configID uuid.UUID) ([]byte, error) {
	b, ok := f.rows[configID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return b, nil
}

func (f *fakeDirCredStore) SetSealed(_ context.Context, _, configID uuid.UUID, sealed []byte) error {
	f.rows[configID] = sealed
	return nil
}

func (f *fakeDirCredStore) DeleteSealed(_ context.Context, _, configID uuid.UUID) error {
	if _, ok := f.rows[configID]; !ok {
		return repository.ErrNotFound
	}
	delete(f.rows, configID)
	return nil
}

func TestOIDCHandler_DirectoryCredentialLifecycle(t *testing.T) {
	h, configs, tenantID := newTestOIDCHandler(t, 10)
	vault, err := identity.NewCredentialVault(newFakeDirCredStore(), policy.PassthroughWrapper{})
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	h.WithDirectoryCredentials(vault)
	mux := http.NewServeMux()
	h.Register(mux)

	cfg, err := configs.Create(t.Context(), tenantID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "client-1",
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("seed config: %v", err)
	}
	credURL := "/api/v1/tenants/" + tenantID.String() + "/idp-configs/" + cfg.ID.String() + "/directory-credential"

	// Precondition: not configured.
	w := oidcDo(t, mux, "GET", credURL, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get (precondition): got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeConfigured(t, w.Body.Bytes()); got {
		t.Fatal("precondition: configured=true, want false")
	}

	// Set.
	w = oidcDo(t, mux, "PUT", credURL, map[string]any{
		"base_url": "https://acme.okta.com",
		"token":    "ssws-secret",
		"subject":  "admin@acme.com",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("put: got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeConfigured(t, w.Body.Bytes()); !got {
		t.Fatal("put: configured=false, want true")
	}

	// The set response must never echo the secret back.
	if body := w.Body.String(); containsStr(body, "ssws-secret") {
		t.Fatalf("put response leaks the token: %s", body)
	}

	// Get reflects configured.
	w = oidcDo(t, mux, "GET", credURL, nil)
	if w.Code != http.StatusOK || !decodeConfigured(t, w.Body.Bytes()) {
		t.Fatalf("get after put: code=%d configured wanted true", w.Code)
	}

	// Delete.
	w = oidcDo(t, mux, "DELETE", credURL, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d", w.Code)
	}
	// Delete again is 404 (nothing stored).
	w = oidcDo(t, mux, "DELETE", credURL, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete absent: got %d, want 404", w.Code)
	}
}

func TestOIDCHandler_DirectoryCredentialValidation(t *testing.T) {
	h, configs, tenantID := newTestOIDCHandler(t, 10)
	vault, err := identity.NewCredentialVault(newFakeDirCredStore(), policy.PassthroughWrapper{})
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	h.WithDirectoryCredentials(vault)
	mux := http.NewServeMux()
	h.Register(mux)

	cfg, err := configs.Create(t.Context(), tenantID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta, IssuerURL: "https://acme.okta.com",
		ClientID: "c", Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed config: %v", err)
	}
	base := "/api/v1/tenants/" + tenantID.String() + "/idp-configs/"

	// Empty token is a 400.
	w := oidcDo(t, mux, "PUT", base+cfg.ID.String()+"/directory-credential", map[string]any{"token": ""})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty token: got %d, want 400", w.Code)
	}

	// Unknown config id is a 404 on both set and get.
	unknown := base + uuid.New().String() + "/directory-credential"
	w = oidcDo(t, mux, "PUT", unknown, map[string]any{"token": "tok"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("put unknown config: got %d, want 404", w.Code)
	}
	w = oidcDo(t, mux, "GET", unknown, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get unknown config: got %d, want 404", w.Code)
	}
}

// Without a vault the sub-resource routes are not registered at all.
func TestOIDCHandler_DirectoryCredentialRoutesUnmountedByDefault(t *testing.T) {
	h, configs, tenantID := newTestOIDCHandler(t, 10)
	mux := http.NewServeMux()
	h.Register(mux)

	cfg, err := configs.Create(t.Context(), tenantID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta, IssuerURL: "https://acme.okta.com",
		ClientID: "c", Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed config: %v", err)
	}
	credURL := "/api/v1/tenants/" + tenantID.String() + "/idp-configs/" + cfg.ID.String() + "/directory-credential"
	w := oidcDo(t, mux, "GET", credURL, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("default (no vault): got %d, want 404 (route unmounted)", w.Code)
	}
}

func decodeConfigured(t *testing.T, body []byte) bool {
	t.Helper()
	var resp struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode status: %v (body=%s)", err, string(body))
	}
	return resp.Configured
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
