package middleware

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope reported on every span
// this middleware produces.
const tracerName = "github.com/kennguy3n/visible-fishbone/internal/middleware"

// Tracing returns an HTTP middleware that opens an OpenTelemetry
// span per request. It:
//
//   - extracts any inbound W3C trace context from the request
//     headers (so a span started upstream becomes this span's
//     parent), using the globally installed propagator;
//   - starts a server span named "<METHOD> <normalised-route>"
//     and threads it onto the request context, so the span (and
//     thus the trace ID) is available to every downstream layer
//     and handler;
//   - records method / route / status-code attributes, and — by
//     reading the late-bound RequestMeta after the handler returns
//     — the resolved tenant_id, mirroring how the Logging
//     middleware captures identity.
//
// It is a no-op-friendly wrapper around the global tracer: when
// otel.InitTracer ran with no exporter the global tracer is the
// SDK no-op, so spans are cheap and discarded. Install this
// middleware AFTER Logging (so RequestMeta is present) and BEFORE
// Auth (so the span wraps authentication latency).
func Tracing() func(http.Handler) http.Handler {
	tracer := otel.Tracer(tracerName)
	propagator := otel.GetTextMapPropagator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			route := normalizeRoute(r.URL.Path)
			ctx, span := tracer.Start(ctx, r.Method+" "+route,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("url.path", r.URL.Path),
					attribute.String("http.route", route),
				),
			)
			defer span.End()

			rec := &statusRecorder{ResponseWriter: w}
			r = r.WithContext(ctx)
			next.ServeHTTP(rec, r)

			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			span.SetAttributes(attribute.Int("http.response.status_code", status))

			// Tenant ID is resolved by the Auth middleware, which
			// runs inside this span and writes through the
			// late-bound RequestMeta pointer installed by Logging.
			// Fall back to the context value for chains that wire
			// the tenant guard without Logging.
			if meta := RequestMetaFromContext(r.Context()); meta != nil {
				if tid := meta.TenantID(); tid != uuid.Nil {
					span.SetAttributes(attribute.String("tenant_id", tid.String()))
				}
			} else if tid := TenantIDFromContext(r.Context()); tid != uuid.Nil {
				span.SetAttributes(attribute.String("tenant_id", tid.String()))
			}

			// Mark 5xx as an error span so trace backends surface
			// it; 4xx is a client problem, not a server fault.
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
		})
	}
}

// normalizeRoute collapses high-cardinality path segments (UUIDs,
// numeric IDs) to a fixed ":id" token so span names group by
// route template rather than exploding per tenant/resource. Kept
// local to the middleware package so it carries no dependency on
// the metrics package.
func normalizeRoute(path string) string {
	if path == "" || path == "/" {
		return path
	}
	rewrite := false
	for _, seg := range strings.Split(path, "/") {
		if isVariableSegment(seg) {
			rewrite = true
			break
		}
	}
	if !rewrite {
		return path
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if isVariableSegment(seg) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

func isVariableSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] < '0' || seg[i] > '9' {
			return isHyphenatedUUID(seg)
		}
	}
	return true // all digits
}

func isHyphenatedUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
