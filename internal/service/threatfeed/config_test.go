package threatfeed

import (
	"testing"
	"time"
)

// envFunc builds a getenv closure over a map.
func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Fatal("managed content must default ON (no-ops)")
	}
	if cfg.RefreshInterval != DefaultRefreshInterval || cfg.KeyID != DefaultKeyID || cfg.Subject != DefaultSubject {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if cfg.MaxIndicators != DefaultMaxIndicators || cfg.HistoryKeep != DefaultHistoryKeep {
		t.Fatalf("bound defaults wrong: %+v", cfg)
	}
	if cfg.HalfLife != DefaultHalfLife || cfg.HTTPTimeout != DefaultHTTPTimeout || cfg.MaxFeedBytes != DefaultMaxFeedBytes {
		t.Fatalf("cost defaults wrong: %+v", cfg)
	}
}

func TestLoadConfig_EmptyEnvIsDefault(t *testing.T) {
	t.Parallel()
	if got := LoadConfig(envFunc(nil)); got != DefaultConfig() {
		t.Fatalf("empty env should equal default: %+v", got)
	}
}

func TestLoadConfig_Overrides(t *testing.T) {
	t.Parallel()
	cfg := LoadConfig(envFunc(map[string]string{
		EnvEnabled:         "false",
		EnvPublish:         "off",
		EnvRefreshInterval: "15m",
		EnvHalfLife:        "240h",
		EnvHTTPTimeout:     "5s",
		EnvSigningKeyHex:   "  abcdef  ",
		EnvKeyID:           "  my-key  ",
		EnvSubject:         " sng.custom ",
		EnvMaxIndicators:   "1000",
		EnvHistoryKeep:     "3",
		EnvMaxFeedBytes:    "2048",
	}))
	if cfg.Enabled {
		t.Fatal("kill switch off not honored")
	}
	if cfg.Publish {
		t.Fatal("publish off not honored")
	}
	if cfg.RefreshInterval != 15*time.Minute || cfg.HalfLife != 240*time.Hour || cfg.HTTPTimeout != 5*time.Second {
		t.Fatalf("durations not parsed: %+v", cfg)
	}
	if cfg.SigningKeyHex != "abcdef" || cfg.KeyID != "my-key" || cfg.Subject != "sng.custom" {
		t.Fatalf("strings not trimmed: %+v", cfg)
	}
	if cfg.MaxIndicators != 1000 || cfg.HistoryKeep != 3 || cfg.MaxFeedBytes != 2048 {
		t.Fatalf("numeric overrides not applied: %+v", cfg)
	}
}

func TestLoadConfig_MalformedFallsBackToDefault(t *testing.T) {
	t.Parallel()
	def := DefaultConfig()
	cfg := LoadConfig(envFunc(map[string]string{
		EnvRefreshInterval: "not-a-duration",
		EnvHalfLife:        "-5h", // non-positive rejected
		EnvMaxIndicators:   "0",   // non-positive rejected
		EnvHistoryKeep:     "abc",
		EnvMaxFeedBytes:    "-1",
	}))
	if cfg.RefreshInterval != def.RefreshInterval {
		t.Fatalf("bad duration should fall back: %v", cfg.RefreshInterval)
	}
	if cfg.HalfLife != def.HalfLife {
		t.Fatalf("negative half-life should fall back: %v", cfg.HalfLife)
	}
	if cfg.MaxIndicators != def.MaxIndicators || cfg.HistoryKeep != def.HistoryKeep || cfg.MaxFeedBytes != def.MaxFeedBytes {
		t.Fatalf("bad numerics should fall back: %+v", cfg)
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()
	truthy := []string{"1", "t", "true", "TRUE", "yes", "Y", "on", "enabled"}
	for _, v := range truthy {
		if !parseBool(v, false) {
			t.Fatalf("%q should parse truthy", v)
		}
	}
	falsey := []string{"0", "f", "false", "no", "N", "off", "disabled"}
	for _, v := range falsey {
		if parseBool(v, true) {
			t.Fatalf("%q should parse falsey", v)
		}
	}
	if !parseBool("garbage", true) {
		t.Fatal("unrecognized should keep def=true")
	}
	if parseBool("garbage", false) {
		t.Fatal("unrecognized should keep def=false")
	}
}
