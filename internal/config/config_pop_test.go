// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"strings"
	"testing"
	"time"
)

// TestPoPDefaults pins the documented defaults for the Cloud PoP
// knobs so a future change to a default is a deliberate, reviewed
// edit rather than an accidental drift.
func TestPoPDefaults(t *testing.T) {
	clearAll(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.PoP
	if p.RegistryRefreshInterval != 30*time.Second {
		t.Errorf("RegistryRefreshInterval = %s, want 30s", p.RegistryRefreshInterval)
	}
	if p.HealthTTL != 90*time.Second {
		t.Errorf("HealthTTL = %s, want 90s", p.HealthTTL)
	}
	if p.HighWaterFraction != 0.85 {
		t.Errorf("HighWaterFraction = %v, want 0.85", p.HighWaterFraction)
	}
	if p.GeoDNSHostname != "edge.sng.example.com" {
		t.Errorf("GeoDNSHostname = %q, want edge.sng.example.com", p.GeoDNSHostname)
	}
	if p.GeoDNSRoutingPolicy != "latency" {
		t.Errorf("GeoDNSRoutingPolicy = %q, want latency", p.GeoDNSRoutingPolicy)
	}
	if p.GeoDNSTTL != 30*time.Second {
		t.Errorf("GeoDNSTTL = %s, want 30s", p.GeoDNSTTL)
	}
	if p.GeoDNSPublishInterval != 30*time.Second {
		t.Errorf("GeoDNSPublishInterval = %s, want 30s", p.GeoDNSPublishInterval)
	}
	if !p.RebalanceEnabled {
		t.Error("RebalanceEnabled = false, want true (default on)")
	}
	if p.RebalanceInterval != 60*time.Second {
		t.Errorf("RebalanceInterval = %s, want 60s", p.RebalanceInterval)
	}
}

// TestPoPEnvOverridesReachConfig confirms each PoP env var is wired
// through Load into the struct.
func TestPoPEnvOverridesReachConfig(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"POP_REGISTRY_REFRESH_INTERVAL": "10s",
		"POP_HEALTH_TTL":                "45s",
		"POP_HIGH_WATER_FRACTION":       "0.7",
		"POP_GEODNS_HOSTNAME":           "pop.acme.example",
		"POP_GEODNS_ROUTING_POLICY":     "weighted",
		"POP_GEODNS_TTL":                "5s",
		"POP_GEODNS_PUBLISH_INTERVAL":   "20s",
		"POP_REBALANCE_ENABLED":         "false",
		"POP_REBALANCE_INTERVAL":        "2m",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.PoP
	if p.RegistryRefreshInterval != 10*time.Second {
		t.Errorf("RegistryRefreshInterval = %s, want 10s", p.RegistryRefreshInterval)
	}
	if p.HealthTTL != 45*time.Second {
		t.Errorf("HealthTTL = %s, want 45s", p.HealthTTL)
	}
	if p.HighWaterFraction != 0.7 {
		t.Errorf("HighWaterFraction = %v, want 0.7", p.HighWaterFraction)
	}
	if p.GeoDNSHostname != "pop.acme.example" {
		t.Errorf("GeoDNSHostname = %q, want pop.acme.example", p.GeoDNSHostname)
	}
	if p.GeoDNSRoutingPolicy != "weighted" {
		t.Errorf("GeoDNSRoutingPolicy = %q, want weighted", p.GeoDNSRoutingPolicy)
	}
	if p.GeoDNSTTL != 5*time.Second {
		t.Errorf("GeoDNSTTL = %s, want 5s", p.GeoDNSTTL)
	}
	if p.GeoDNSPublishInterval != 20*time.Second {
		t.Errorf("GeoDNSPublishInterval = %s, want 20s", p.GeoDNSPublishInterval)
	}
	if p.RebalanceEnabled {
		t.Error("RebalanceEnabled = true, want false")
	}
	if p.RebalanceInterval != 2*time.Minute {
		t.Errorf("RebalanceInterval = %s, want 2m", p.RebalanceInterval)
	}
}

// TestPoPStrictParseRejectsBadValues confirms the strict parser
// fails boot (rather than silently reverting to a default) on an
// operator typo in a load-bearing PoP knob, naming the offending
// env var in the error.
func TestPoPStrictParseRejectsBadValues(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		value string
	}{
		{"bad duration", "POP_HEALTH_TTL", "45sec"},
		{"bad float", "POP_HIGH_WATER_FRACTION", "high"},
		{"bad bool", "POP_REBALANCE_ENABLED", "maybe"},
		{"bad refresh interval", "POP_REGISTRY_REFRESH_INTERVAL", "soon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{tc.env: tc.value})
			_, err := Load()
			if err == nil {
				t.Fatalf("expected strict-parse error for %s", tc.env)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Errorf("error should name %s: %v", tc.env, err)
			}
		})
	}
}

// TestPoPValidationRejectsOutOfRange confirms that syntactically valid
// but semantically out-of-range PoP knobs fail boot in validate()
// (rather than being silently ignored by the service-level options and
// falling back to a default). A zero refresh interval is especially
// load-bearing: it would panic time.NewTicker at runtime.
func TestPoPValidationRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		value string
	}{
		{"high-water above 1", "POP_HIGH_WATER_FRACTION", "1.5"},
		{"high-water zero", "POP_HIGH_WATER_FRACTION", "0"},
		{"high-water negative", "POP_HIGH_WATER_FRACTION", "-0.1"},
		// strconv.ParseFloat accepts "NaN"/"Inf"; every NaN comparison is
		// false, so the in-range check must be written so NaN/Inf fail.
		{"high-water NaN", "POP_HIGH_WATER_FRACTION", "NaN"},
		{"high-water +Inf", "POP_HIGH_WATER_FRACTION", "+Inf"},
		{"zero refresh interval", "POP_REGISTRY_REFRESH_INTERVAL", "0s"},
		{"zero health ttl", "POP_HEALTH_TTL", "0s"},
		{"zero geodns ttl", "POP_GEODNS_TTL", "0s"},
		{"zero geodns publish", "POP_GEODNS_PUBLISH_INTERVAL", "0s"},
		{"zero rebalance interval", "POP_REBALANCE_INTERVAL", "0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{tc.env: tc.value})
			_, err := Load()
			if err == nil {
				t.Fatalf("expected validation error for %s=%s", tc.env, tc.value)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Errorf("error should name %s: %v", tc.env, err)
			}
		})
	}
}

// TestPoPValidationAcceptsBoundary confirms the inclusive upper bound
// (1.0) on the high-water fraction is accepted.
func TestPoPValidationAcceptsBoundary(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{"POP_HIGH_WATER_FRACTION": "1"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with POP_HIGH_WATER_FRACTION=1: %v", err)
	}
	if cfg.PoP.HighWaterFraction != 1 {
		t.Errorf("HighWaterFraction = %v, want 1", cfg.PoP.HighWaterFraction)
	}
}
