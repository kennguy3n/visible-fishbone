// Package otel wires the ShieldNet Gateway control plane to
// OpenTelemetry distributed tracing. It owns the one-time SDK
// bootstrap (exporter + resource + batch span processor + global
// propagator) and hands back a shutdown closure the entrypoint
// flushes on graceful stop.
//
// The control plane already carries the OTel API/SDK as
// transitive dependencies; this package is the single place that
// turns the config knob (Telemetry.OTLPEndpoint) into a live
// pipeline. When the endpoint is unset the global tracer stays the
// no-op implementation — but the W3C TraceContext + Baggage
// propagator is installed regardless, so inbound `traceparent`
// headers still thread a trace ID through request context for log
// correlation even with the exporter disabled.
package otel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// ShutdownFunc flushes any buffered spans and tears down the
// tracer provider. It is safe to call with a deadline-bearing
// context so a slow collector cannot hang process shutdown
// indefinitely. Always non-nil from InitTracer (a no-op closure
// when tracing is disabled), so callers can defer it
// unconditionally.
type ShutdownFunc func(context.Context) error

// exporterTimeout bounds a single OTLP export attempt so a wedged
// collector cannot stall the batch processor's flush.
const exporterTimeout = 10 * time.Second

// InitTracer configures the global OpenTelemetry tracer provider
// and propagator from the Telemetry config.
//
// serviceName and environment populate the OTel resource
// (service.name / deployment.environment); they live on the
// top-level Config rather than Telemetry, so the entrypoint passes
// them explicitly. cfg.ServiceVersion populates service.version.
//
// Behaviour:
//   - The W3C TraceContext + Baggage composite propagator is
//     installed in every case (even when the exporter is
//     disabled) so cross-service context propagation works.
//   - When cfg.OTLPEndpoint is empty, no exporter or provider is
//     installed (the global tracer remains a no-op) and the
//     returned shutdown is a no-op.
//   - Otherwise an OTLP/HTTP exporter is wired to a batch span
//     processor behind a freshly built TracerProvider set as the
//     global default.
//
// The returned ShutdownFunc is always non-nil.
func InitTracer(ctx context.Context, cfg config.Telemetry, serviceName, environment string) (ShutdownFunc, error) {
	// Composite propagator first — independent of whether the
	// exporter is enabled.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	noop := func(context.Context) error { return nil }

	endpoint := strings.TrimSpace(cfg.OTLPEndpoint)
	if endpoint == "" {
		return noop, nil
	}

	exporter, err := newExporter(ctx, endpoint)
	if err != nil {
		return noop, fmt.Errorf("otel: build OTLP exporter: %w", err)
	}

	res, err := newResource(ctx, serviceName, cfg.ServiceVersion, environment)
	if err != nil {
		// The exporter was created but the provider is not wired
		// yet; shut the exporter down so its connection does not
		// leak.
		_ = exporter.Shutdown(ctx)
		return noop, fmt.Errorf("otel: build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// newExporter builds the OTLP/HTTP trace exporter. The endpoint is
// interpreted the way the OTEL_EXPORTER_OTLP_ENDPOINT convention
// expects: a full URL (`https://collector:4318`) selects the
// scheme and TLS mode directly, while a bare `host:port` is
// treated as a plaintext target (WithInsecure) — the common
// in-cluster / sidecar collector shape.
func newExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithTimeout(exporterTimeout),
	}
	if strings.Contains(endpoint, "://") {
		opts = append(opts, otlptracehttp.WithEndpointURL(endpoint))
	} else {
		opts = append(opts,
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithInsecure(),
		)
	}
	return otlptracehttp.New(ctx, opts...)
}

// newResource assembles the OTel resource describing this service
// instance. service.version is omitted when unset rather than
// emitting an empty attribute.
func newResource(ctx context.Context, serviceName, serviceVersion, environment string) (*resource.Resource, error) {
	if serviceName == "" {
		serviceName = "sng-control"
	}
	base := []resource.Option{
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironment(environment),
		),
	}
	if serviceVersion != "" {
		base = append(base, resource.WithAttributes(semconv.ServiceVersion(serviceVersion)))
	}
	// Merge with SDK-detected defaults (host, OS, process, and any
	// OTEL_RESOURCE_ATTRIBUTES the operator sets) so the explicit
	// attributes win on conflict.
	return resource.New(ctx, base...)
}
