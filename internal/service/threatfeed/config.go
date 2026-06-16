package threatfeed

import (
	"strconv"
	"strings"
	"time"
)

// Environment variables that tune the managed threat-content engine.
// All are optional: the zero-config defaults ship curated content to
// every tenant (no-ops). MANAGED_THREAT_CONTENT_ENABLED is the kill
// switch — set it to a falsey value to disable ingestion fleet-wide
// without a deploy.
const (
	EnvEnabled         = "MANAGED_THREAT_CONTENT_ENABLED"
	EnvRefreshInterval = "MANAGED_THREAT_CONTENT_REFRESH_INTERVAL"
	EnvSigningKeyHex   = "MANAGED_THREAT_CONTENT_SIGNING_KEY_HEX"
	EnvKeyID           = "MANAGED_THREAT_CONTENT_KEY_ID"
	EnvSubject         = "MANAGED_THREAT_CONTENT_SUBJECT"
	EnvPublish         = "MANAGED_THREAT_CONTENT_PUBLISH"
	EnvMaxIndicators   = "MANAGED_THREAT_CONTENT_MAX_INDICATORS"
	EnvHistoryKeep     = "MANAGED_THREAT_CONTENT_HISTORY_KEEP"
	EnvHalfLife        = "MANAGED_THREAT_CONTENT_HALF_LIFE"
	EnvHTTPTimeout     = "MANAGED_THREAT_CONTENT_HTTP_TIMEOUT"
	EnvMaxFeedBytes    = "MANAGED_THREAT_CONTENT_MAX_FEED_BYTES"
)

// Defaults for the engine's bounded-cost knobs.
const (
	DefaultRefreshInterval = time.Hour
	DefaultKeyID           = "sng-managed-threat-content"
	DefaultSubject         = "sng.platform.threatcontent.bundle.v1"
	// DefaultMaxIndicators caps a single bundle. 500k indicators of
	// the built-in feeds fit comfortably in a few tens of MB and bound
	// worst-case memory and bundle size at fleet scale.
	DefaultMaxIndicators = 500_000
	// DefaultHistoryKeep is how many recent bundle versions are
	// retained for rollback/audit before pruning.
	DefaultHistoryKeep = 10
)

// Config is the resolved managed-content engine configuration.
type Config struct {
	// Enabled is the kill switch. Default true (managed content is on).
	Enabled bool
	// RefreshInterval bounds how often ingestion runs centrally.
	RefreshInterval time.Duration
	// SigningKeyHex is the hex-encoded Ed25519 key (seed or expanded).
	// Empty mints an ephemeral key with a loud warning.
	SigningKeyHex string
	// KeyID labels the signing key in the bundle envelope.
	KeyID string
	// Subject is the NATS subject the signed bundle is published on.
	Subject string
	// Publish enables NATS distribution of the bundle (in addition to
	// durable persistence). Default true.
	Publish bool
	// MaxIndicators caps a single bundle's indicator count.
	MaxIndicators int
	// HistoryKeep is the retained bundle-version count.
	HistoryKeep int
	// HalfLife is the recency-decay half-life.
	HalfLife time.Duration
	// HTTPTimeout bounds a single feed fetch.
	HTTPTimeout time.Duration
	// MaxFeedBytes caps a single feed response.
	MaxFeedBytes int64
}

// DefaultConfig returns the zero-config managed-content defaults
// (enabled, hourly, bounded).
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		RefreshInterval: DefaultRefreshInterval,
		KeyID:           DefaultKeyID,
		Subject:         DefaultSubject,
		Publish:         true,
		MaxIndicators:   DefaultMaxIndicators,
		HistoryKeep:     DefaultHistoryKeep,
		HalfLife:        DefaultHalfLife,
		HTTPTimeout:     DefaultHTTPTimeout,
		MaxFeedBytes:    DefaultMaxFeedBytes,
	}
}

// LoadConfig resolves the engine configuration from environment
// variables via getenv (os.Getenv in production, a map in tests),
// starting from DefaultConfig. Malformed values fall back to the
// default for that field rather than failing startup — managed content
// should degrade to safe defaults, never block the control plane from
// booting.
func LoadConfig(getenv func(string) string) Config {
	cfg := DefaultConfig()
	if v := getenv(EnvEnabled); v != "" {
		cfg.Enabled = parseBool(v, cfg.Enabled)
	}
	if v := getenv(EnvPublish); v != "" {
		cfg.Publish = parseBool(v, cfg.Publish)
	}
	if v := getenv(EnvRefreshInterval); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.RefreshInterval = d
		}
	}
	if v := getenv(EnvHalfLife); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.HalfLife = d
		}
	}
	if v := getenv(EnvHTTPTimeout); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.HTTPTimeout = d
		}
	}
	if v := getenv(EnvSigningKeyHex); v != "" {
		cfg.SigningKeyHex = strings.TrimSpace(v)
	}
	if v := getenv(EnvKeyID); v != "" {
		cfg.KeyID = strings.TrimSpace(v)
	}
	if v := getenv(EnvSubject); v != "" {
		cfg.Subject = strings.TrimSpace(v)
	}
	if v := getenv(EnvMaxIndicators); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxIndicators = n
		}
	}
	if v := getenv(EnvHistoryKeep); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HistoryKeep = n
		}
	}
	if v := getenv(EnvMaxFeedBytes); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.MaxFeedBytes = n
		}
	}
	return cfg
}

// parseBool interprets common truthy/falsey spellings, falling back to
// def for anything unrecognized.
func parseBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "yes", "y", "on", "enabled":
		return true
	case "0", "f", "false", "no", "n", "off", "disabled":
		return false
	default:
		return def
	}
}
