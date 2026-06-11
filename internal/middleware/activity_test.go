package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

type capturingObserver struct {
	ids []uuid.UUID
}

func (c *capturingObserver) Observe(tenantID uuid.UUID, _ time.Time) {
	c.ids = append(c.ids, tenantID)
}

func TestRecordActivity_ObservesResolvedTenant(t *testing.T) {
	obs := &capturingObserver{}
	tid := uuid.New()

	var served bool
	h := RecordActivity(obs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req = req.WithContext(context.WithValue(req.Context(), keyTenantID, tid))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !served {
		t.Fatal("handler not invoked")
	}
	if len(obs.ids) != 1 || obs.ids[0] != tid {
		t.Fatalf("observed %v, want [%v]", obs.ids, tid)
	}
}

func TestRecordActivity_SkipsWhenNoTenant(t *testing.T) {
	obs := &capturingObserver{}
	h := RecordActivity(obs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil) // no tenant in context
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(obs.ids) != 0 {
		t.Fatalf("observed %v, want none", obs.ids)
	}
}

func TestRecordActivity_NilObserverIsPassThrough(t *testing.T) {
	var served bool
	h := RecordActivity(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req = req.WithContext(context.WithValue(req.Context(), keyTenantID, uuid.New()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !served || rec.Code != http.StatusOK {
		t.Fatalf("nil observer should pass through, served=%v code=%d", served, rec.Code)
	}
}
