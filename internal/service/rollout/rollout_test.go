package rollout

import (
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestStateValidAndSemantics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s         State
		valid     bool
		enforces  bool
		evaluates bool
	}{
		{StateOff, true, false, false},
		{StateMonitor, true, false, true},
		{StateEnforce, true, true, true},
		{State("bogus"), false, false, false},
		{State(""), false, false, false},
	}
	for _, c := range cases {
		if got := c.s.Valid(); got != c.valid {
			t.Errorf("State(%q).Valid() = %v, want %v", c.s, got, c.valid)
		}
		if got := c.s.Enforces(); got != c.enforces {
			t.Errorf("State(%q).Enforces() = %v, want %v", c.s, got, c.enforces)
		}
		if got := c.s.Evaluates(); got != c.evaluates {
			t.Errorf("State(%q).Evaluates() = %v, want %v", c.s, got, c.evaluates)
		}
	}
}

func TestCapabilityValidAndAllCapabilities(t *testing.T) {
	t.Parallel()
	for _, c := range AllCapabilities() {
		if !c.Valid() {
			t.Errorf("AllCapabilities returned invalid capability %q", c)
		}
	}
	if Capability("nope").Valid() {
		t.Error("unknown capability reported valid")
	}
	// The three gates the framework was built for must all be present.
	want := map[Capability]bool{
		CapabilityClamAVSWG:        false,
		CapabilityNoOpsAutoEnforce: false,
		CapabilityIDPDirectorySync: false,
		CapabilityMarginAutopilot:  false,
	}
	for _, c := range AllCapabilities() {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for c, seen := range want {
		if !seen {
			t.Errorf("AllCapabilities missing %q", c)
		}
	}
}

func TestValidateTransition(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		from, to  State
		allowSkip bool
		wantErr   error
	}{
		{"off->monitor advance", StateOff, StateMonitor, false, nil},
		{"monitor->enforce advance", StateMonitor, StateEnforce, false, nil},
		{"enforce->monitor rollback", StateEnforce, StateMonitor, false, nil},
		{"monitor->off rollback", StateMonitor, StateOff, false, nil},
		{"enforce->off rollback", StateEnforce, StateOff, false, nil},
		{"off->enforce skip without flag", StateOff, StateEnforce, false, ErrSkipNotAllowed},
		{"off->enforce skip with flag", StateOff, StateEnforce, true, nil},
		{"off->off no-op", StateOff, StateOff, false, ErrNoOpTransition},
		{"monitor->monitor no-op", StateMonitor, StateMonitor, true, ErrNoOpTransition},
		{"invalid target", StateOff, State("bogus"), true, ErrInvalidState},
		{"invalid source", State("bogus"), StateOff, true, ErrInvalidState},
		// A rollback never needs the skip flag, even the two-step one.
		{"enforce->off rollback two-step", StateEnforce, StateOff, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateTransition(c.from, c.to, c.allowSkip)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("validateTransition(%s,%s,%v) = %v, want nil", c.from, c.to, c.allowSkip, err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("validateTransition(%s,%s,%v) = %v, want %v", c.from, c.to, c.allowSkip, err, c.wantErr)
			}
			// Every transition error must also be a 400-class invalid-argument.
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("transition error %v does not wrap ErrInvalidArgument", err)
			}
		})
	}
}

func TestMonitorMetricsRates(t *testing.T) {
	t.Parallel()
	m := MonitorMetrics{Samples: 200, Errors: 10, Denies: 50}
	if got := m.ErrorRate(); got != 0.05 {
		t.Errorf("ErrorRate = %v, want 0.05", got)
	}
	if got := m.DenyRate(); got != 0.25 {
		t.Errorf("DenyRate = %v, want 0.25", got)
	}
	zero := MonitorMetrics{}
	if zero.ErrorRate() != 0 || zero.DenyRate() != 0 {
		t.Error("rates on zero samples must be 0, not NaN")
	}
}

func TestMonitorMetricsBreach(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		m        MonitorMetrics
		t        Threshold
		breached bool
	}{
		{
			name:     "disabled threshold never breaches",
			m:        MonitorMetrics{Samples: 100, Errors: 100},
			t:        Threshold{},
			breached: false,
		},
		{
			name:     "below min samples does not breach",
			m:        MonitorMetrics{Samples: 5, Errors: 5},
			t:        Threshold{MaxErrorRate: 0.1, MinSamples: 50},
			breached: false,
		},
		{
			name:     "error rate over threshold breaches",
			m:        MonitorMetrics{Samples: 100, Errors: 20},
			t:        Threshold{MaxErrorRate: 0.1, MinSamples: 50},
			breached: true,
		},
		{
			name:     "error rate at threshold does not breach",
			m:        MonitorMetrics{Samples: 100, Errors: 10},
			t:        Threshold{MaxErrorRate: 0.1, MinSamples: 50},
			breached: false,
		},
		{
			name:     "deny rate over threshold breaches",
			m:        MonitorMetrics{Samples: 100, Denies: 60},
			t:        Threshold{MaxDenyRate: 0.5, MinSamples: 50},
			breached: true,
		},
		{
			name:     "min samples zero treated as one",
			m:        MonitorMetrics{Samples: 1, Errors: 1},
			t:        Threshold{MaxErrorRate: 0.1},
			breached: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, breached := c.m.Breach(c.t)
			if breached != c.breached {
				t.Fatalf("Breach = %v, want %v (reason %q)", breached, c.breached, reason)
			}
			if breached && reason == "" {
				t.Fatal("breach must carry a non-empty reason")
			}
		})
	}
}
