package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// withRecorder installs an isolated SDK tracer provider backed by
// an in-memory span recorder as the global provider for the test,
// restoring the prior globals afterwards.
func withRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return sr
}

func attrMap(span sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	out := make(map[attribute.Key]attribute.Value)
	for _, kv := range span.Attributes() {
		out[kv.Key] = kv.Value
	}
	return out
}

func TestTracingRecordsServerSpan(t *testing.T) {
	sr := withRecorder(t)

	h := Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/42/devices", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	span := spans[0]
	if want := "GET /api/v1/tenants/:id/devices"; span.Name() != want {
		t.Errorf("span name = %q, want %q", span.Name(), want)
	}
	if span.SpanKind() != trace.SpanKindServer {
		t.Errorf("span kind = %v, want server", span.SpanKind())
	}
	attrs := attrMap(span)
	if got := attrs[attribute.Key("http.response.status_code")].AsInt64(); got != http.StatusOK {
		t.Errorf("status_code attr = %d, want 200", got)
	}
	if got := attrs[attribute.Key("http.route")].AsString(); got != "/api/v1/tenants/:id/devices" {
		t.Errorf("http.route attr = %q", got)
	}
	if got := attrs[attribute.Key("url.path")].AsString(); got != "/api/v1/tenants/42/devices" {
		t.Errorf("url.path attr = %q, want raw path", got)
	}
}

func TestTracingMarks5xxAsError(t *testing.T) {
	sr := withRecorder(t)
	h := Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	if spans[0].Status().Code != codes.Error {
		t.Errorf("span status = %v, want Error for 5xx", spans[0].Status().Code)
	}
}

func TestTracingExtractsParentContext(t *testing.T) {
	sr := withRecorder(t)
	h := Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// Valid W3C traceparent: version-traceid-spanid-flags.
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	if got := spans[0].SpanContext().TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace id = %q, want propagated parent trace id", got)
	}
	if !spans[0].Parent().IsValid() {
		t.Error("span has no valid parent; traceparent was not extracted")
	}
}

// TestTracingRecordsTenantFromRequestMeta verifies the tenant_id
// span attribute is sourced from the late-bound RequestMeta
// pointer that inner middleware (Auth) writes through — the only
// mechanism that works given immutable request contexts.
func TestTracingRecordsTenantFromRequestMeta(t *testing.T) {
	sr := withRecorder(t)
	tenant := uuid.New()

	// Outer: install the RequestMeta pointer the way Logging does.
	// Inner (under Tracing): simulate Auth resolving the tenant by
	// writing through that same pointer.
	h := Logging(slog.New(slog.NewTextHandler(io.Discard, nil)))(
		Tracing()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if meta := RequestMetaFromContext(r.Context()); meta != nil {
				meta.SetTenantID(tenant)
			}
			w.WriteHeader(http.StatusOK)
		})),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	if got := attrMap(spans[0])[attribute.Key("tenant_id")].AsString(); got != tenant.String() {
		t.Errorf("tenant_id attr = %q, want %q", got, tenant.String())
	}
}
