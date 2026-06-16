package threatfeed

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

type fakeDegradedSource struct{ degraded bool }

func (f *fakeDegradedSource) Degraded() bool { return f.degraded }

// gaugeValue gathers reg and returns the value of the named gauge and
// whether it was present.
func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		m := mf.GetMetric()
		if len(m) == 0 {
			return 0, false
		}
		return m[0].GetGauge().GetValue(), true
	}
	return 0, false
}

func TestRegisterDegradedMetric_ReflectsSourceAtScrapeTime(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	src := &fakeDegradedSource{}
	if err := RegisterDegradedMetric(reg, "", src); err != nil {
		t.Fatalf("register: %v", err)
	}
	const name = "sng_threatcontent_degraded"

	if v, ok := gaugeValue(t, reg, name); !ok || v != 0 {
		t.Fatalf("%s = %v (present=%v), want 0 while healthy", name, v, ok)
	}

	// The registered GaugeFunc must re-read the source at the next
	// scrape (no background goroutine, no sampling lag), so flipping the
	// engine's degraded state is reflected immediately on the next
	// gather.
	src.degraded = true
	if v, ok := gaugeValue(t, reg, name); !ok || v != 1 {
		t.Fatalf("%s = %v (present=%v), want 1 after source degraded", name, v, ok)
	}

	src.degraded = false
	if v, ok := gaugeValue(t, reg, name); !ok || v != 0 {
		t.Fatalf("%s = %v (present=%v), want 0 after recovery", name, v, ok)
	}
}

func TestRegisterDegradedMetric_NamespaceOverride(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	if err := RegisterDegradedMetric(reg, "acme", &fakeDegradedSource{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := gaugeValue(t, reg, "acme_threatcontent_degraded"); !ok {
		t.Fatalf("namespace override should register acme_threatcontent_degraded")
	}
}

func TestRegisterDegradedMetric_NilArgsNoop(t *testing.T) {
	t.Parallel()
	if err := RegisterDegradedMetric(nil, "", &fakeDegradedSource{}); err != nil {
		t.Fatalf("nil registerer must be a no-op, got %v", err)
	}
	reg := prometheus.NewRegistry()
	if err := RegisterDegradedMetric(reg, "", nil); err != nil {
		t.Fatalf("nil source must be a no-op, got %v", err)
	}
	if _, ok := gaugeValue(t, reg, "sng_threatcontent_degraded"); ok {
		t.Fatalf("nil source must register nothing")
	}
}

func TestRegisterDegradedMetric_DuplicateRegistrationTolerated(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	src := &fakeDegradedSource{}
	if err := RegisterDegradedMetric(reg, "", src); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// Two engines sharing one registry must not panic or error on the
	// duplicate registration of the equivalent gauge.
	if err := RegisterDegradedMetric(reg, "", src); err != nil {
		t.Fatalf("duplicate register must be tolerated, got %v", err)
	}
}
