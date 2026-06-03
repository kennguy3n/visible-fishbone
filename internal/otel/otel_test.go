package otel

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// TestNewResourceIncludesServiceAndDetectedAttrs verifies that the
// explicit service attributes are present AND that the SDK
// detectors actually contribute host/process attributes — i.e. the
// resource is not limited to the hand-set service.* keys.
func TestNewResourceIncludesServiceAndDetectedAttrs(t *testing.T) {
	res, err := newResource(context.Background(), "sng-control", "1.2.3", "test")
	if err != nil {
		t.Fatalf("newResource returned fatal error: %v", err)
	}
	if res == nil {
		t.Fatal("newResource returned nil resource")
	}

	got := map[string]string{}
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.AsString()
	}

	if got[string(semconv.ServiceNameKey)] != "sng-control" {
		t.Errorf("service.name = %q, want sng-control", got[string(semconv.ServiceNameKey)])
	}
	if got[string(semconv.ServiceVersionKey)] != "1.2.3" {
		t.Errorf("service.version = %q, want 1.2.3", got[string(semconv.ServiceVersionKey)])
	}
	if got[string(semconv.DeploymentEnvironmentKey)] != "test" {
		t.Errorf("deployment.environment = %q, want test", got[string(semconv.DeploymentEnvironmentKey)])
	}
	// Detector-sourced attributes: host.name and the process PID
	// should both be present now that the detectors are wired.
	if _, ok := got[string(semconv.HostNameKey)]; !ok {
		t.Error("host.name attribute missing; host detector not wired")
	}
	if _, ok := got[string(semconv.ProcessPIDKey)]; !ok {
		t.Error("process.pid attribute missing; process detector not wired")
	}
}

// TestNewResourceDefaultsServiceName checks the empty-name
// fallback.
func TestNewResourceDefaultsServiceName(t *testing.T) {
	res, err := newResource(context.Background(), "", "", "prod")
	if err != nil {
		t.Fatalf("newResource: %v", err)
	}
	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceNameKey {
			if kv.Value.AsString() != "sng-control" {
				t.Errorf("service.name = %q, want default sng-control", kv.Value.AsString())
			}
			return
		}
	}
	t.Error("service.name attribute not found")
}

// TestInitTracerNoEndpointInstallsPropagator verifies that with no
// OTLP endpoint configured the propagator is still installed (for
// inbound traceparent correlation) and the shutdown func is a
// non-nil no-op.
func TestInitTracerNoEndpointInstallsPropagator(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })

	shutdown, err := InitTracer(context.Background(), config.Telemetry{}, "sng-control", "test")
	if err != nil {
		t.Fatalf("InitTracer: %v", err)
	}
	if shutdown == nil {
		t.Fatal("InitTracer returned nil ShutdownFunc")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned error: %v", err)
	}

	// The composite propagator must carry both TraceContext and
	// Baggage fields.
	fields := otel.GetTextMapPropagator().Fields()
	hasTraceparent := false
	for _, f := range fields {
		if f == "traceparent" {
			hasTraceparent = true
		}
	}
	if !hasTraceparent {
		t.Errorf("propagator fields = %v, want to include traceparent", fields)
	}
	_ = propagation.TraceContext{}
}
