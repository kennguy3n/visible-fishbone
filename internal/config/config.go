// Package config loads ShieldNet Gateway (SNG) control-plane runtime
// configuration from the environment.
//
// All configuration is environment-driven (12-factor). A `.env` file is
// loaded up front if present, but real values are read from the process
// environment so that container deployments (k8s, ECS, Nomad) work
// without source changes.
//
// The package deliberately has no external dependencies beyond the Go
// standard library so it can be safely imported from tests, tooling,
// and migrations.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment is the deployment stage the service is running in.
type Environment string

const (
	EnvironmentLocal Environment = "local"
	EnvironmentDev   Environment = "dev"
	EnvironmentQA    Environment = "qa"
	EnvironmentUAT   Environment = "uat"
	EnvironmentProd  Environment = "prod"
)

// IsDevelopment reports whether the environment is local or dev.
func (e Environment) IsDevelopment() bool {
	return e == EnvironmentLocal || e == EnvironmentDev
}

// IsProduction reports whether the environment requires production-grade
// security controls. Returns true for UAT and prod; QA, dev, and local
// are exempt (they may legitimately use weak secrets or mock signing
// keys).
func (e Environment) IsProduction() bool {
	return e == EnvironmentUAT || e == EnvironmentProd
}

// Valid reports whether the value is a recognised environment.
func (e Environment) Valid() bool {
	switch e {
	case EnvironmentLocal, EnvironmentDev, EnvironmentQA, EnvironmentUAT, EnvironmentProd:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (e Environment) String() string { return string(e) }

// Config is the top-level service configuration.
//
// All sub-structs are exported so that tests and helper packages can
// build custom configurations without re-reading the environment.
type Config struct {
	Environment Environment
	AppName     string

	Log       Log
	HTTP      HTTP
	NATS      NATS
	Postgres  Postgres
	RateLimit RateLimit
	CORS      CORS
	Webhook   Webhook
	Auth      Auth
	Telemetry Telemetry
}

// Log carries structured-logging configuration.
type Log struct {
	Level  string
	Format string // "json" or "text"
}

// HTTP holds the HTTP server config.
type HTTP struct {
	Host string
	Port int
	// ReadTimeout caps the total time the server spends reading
	// each request, including its body. Mapped to
	// http.Server.ReadTimeout.
	ReadTimeout time.Duration
	// ReadHeaderTimeout caps the time the server spends reading
	// just the request headers, defending against Slowloris-style
	// header-stuffing attacks independent of body upload speed.
	// Mapped to http.Server.ReadHeaderTimeout. Typically shorter
	// than ReadTimeout.
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	// ShutdownTimeout caps how long the graceful shutdown sequence
	// will wait for in-flight requests before forcibly closing
	// connections.
	ShutdownTimeout time.Duration
}

// Addr returns the listen address (host:port).
func (h HTTP) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// NATS contains all NATS / JetStream connection settings.
type NATS struct {
	URL                  string
	Name                 string
	User                 string
	Password             string
	Token                string
	CredsFile            string
	TLSCAFile            string
	TLSCertFile          string
	TLSKeyFile           string
	TLSInsecure          bool
	ReconnectWait        time.Duration
	MaxReconnects        int
	RequestTimeout       time.Duration
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration
	DedupWindow          time.Duration
	Replicas             int
	Storage              string // "file" or "memory"
	FetchBatchSize       int
	FetchMaxWait         time.Duration
	// StreamPrefix is prepended to every JetStream stream name so
	// multiple SNG control planes can share a NATS cluster without
	// colliding (useful in shared-cell deployments). Defaults to
	// "SNG".
	StreamPrefix string
}

// Postgres carries database connection config.
type Postgres struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnTimeout     time.Duration
	// AppRole is the Postgres role the application connects as
	// (defaults to the connection user). Reserved for future
	// privilege-separation: control-plane RLS policies grant
	// SELECT/INSERT/UPDATE on tenant-scoped tables to this role
	// only.
	AppRole string
}

// DSN returns a libpq connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
		int(p.ConnTimeout.Seconds()),
	)
}

// RateLimit configures the per-IP token-bucket rate limiter that
// wraps the HTTP mux. Defaults are tuned for typical operator-console
// click traffic (30 req/s, burst 60). Operators tighten via
// RATE_LIMIT_RATE / RATE_LIMIT_BURST when sitting behind a CDN that
// already coalesces traffic, and disable entirely by setting
// RATE_LIMIT_ENABLED=false (e.g. when a dedicated WAF handles it).
type RateLimit struct {
	Enabled         bool
	Rate            float64
	Burst           int
	CleanupInterval time.Duration
	IdleTTL         time.Duration
	// TrustedProxies is the raw comma-separated list of reverse-proxy
	// CIDR ranges from RATE_LIMIT_TRUSTED_PROXIES. Parsing happens
	// at the wiring layer so a malformed entry fails boot fast
	// rather than silently widening (or narrowing) the trust set.
	//
	// When empty, the limiter buckets on r.RemoteAddr only and
	// ignores X-Forwarded-For / X-Real-IP entirely.
	TrustedProxies string
}

// CORS configures the cross-origin policy applied to every HTTP route.
//
// AllowedOrigins is read from the CORS_ALLOWED_ORIGINS environment
// variable as a comma-separated list. A single "*" entry means
// "echo any origin"; other entries must match the request's Origin
// header exactly (case-insensitive). Defaults to empty.
type CORS struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         time.Duration
}

// Webhook holds outbound webhook delivery configuration.
type Webhook struct {
	// MaxRetries is the maximum number of delivery attempts before
	// a webhook is marked exhausted.
	MaxRetries int
	// InitialDelay is the first retry delay; subsequent delays are
	// exponentially backed off up to MaxDelay.
	InitialDelay time.Duration
	MaxDelay     time.Duration
	// DeliveryTimeout is the per-attempt HTTP client timeout.
	DeliveryTimeout time.Duration
	// SignatureHeader is the HTTP header carrying the HMAC-SHA256
	// signature. Defaults to "X-SNG-Signature".
	SignatureHeader string
}

// Auth carries authentication configuration for the operator-facing
// API.
type Auth struct {
	// JWTSecret is the HMAC key used to sign / verify operator JWTs
	// in development. In production this is replaced by OIDC
	// verification (configured at the gateway level).
	JWTSecret string
	// JWTIssuer is the iss claim accepted on incoming JWTs.
	JWTIssuer string
	// JWTAudience is the aud claim accepted on incoming JWTs.
	JWTAudience string
	// AccessTokenTTL is how long control-plane access tokens last.
	AccessTokenTTL time.Duration
	// APIKeyHeader is the HTTP header carrying API keys for
	// machine-to-machine authentication (defaults to
	// "X-SNG-API-Key").
	APIKeyHeader string
}

// Telemetry carries OTel SDK bridge configuration.
type Telemetry struct {
	// OTLPEndpoint is the OTLP/HTTP collector endpoint. When empty
	// the OTel SDK bridge is disabled and the in-process tracer
	// falls back to the no-op exporter.
	OTLPEndpoint string
	// ServiceVersion populates the OTel resource attribute
	// service.version. Typically the release tag or git SHA.
	ServiceVersion string
}

// Load reads configuration from the environment.
//
// It loads ".env" if present in the working directory (best-effort)
// and then parses all known variables, returning a populated
// [Config].
//
// Required variables: APP_NAME, ENVIRONMENT. Other variables fall
// back to sensible defaults so that scripts and unit tests can run
// without a full environment.
func Load() (Config, error) {
	_ = loadDotEnv(".env")

	cfg := Config{
		Environment: Environment(strings.ToLower(getStr("ENVIRONMENT", string(EnvironmentLocal)))),
		AppName:     getStr("APP_NAME", "sng-control"),

		Log: Log{
			Level:  getStr("LOG_LEVEL", "info"),
			Format: getStr("LOG_FORMAT", "json"),
		},
		HTTP: HTTP{
			Host:              getStr("HTTP_HOST", "0.0.0.0"),
			Port:              getInt("HTTP_PORT", 8080),
			ReadTimeout:       getDuration("HTTP_READ_TIMEOUT", 15*time.Second),
			ReadHeaderTimeout: getDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			WriteTimeout:      getDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
			ShutdownTimeout:   getDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second),
		},
		NATS: NATS{
			URL:                  getStr("NATS_URL", "nats://127.0.0.1:4222"),
			Name:                 getStr("NATS_NAME", "sng-control"),
			User:                 getStr("NATS_USER", ""),
			Password:             getStr("NATS_PASSWORD", ""),
			Token:                getStr("NATS_TOKEN", ""),
			CredsFile:            getStr("NATS_CREDS_FILE", ""),
			TLSCAFile:            getStr("NATS_TLS_CA", ""),
			TLSCertFile:          getStr("NATS_TLS_CERT", ""),
			TLSKeyFile:           getStr("NATS_TLS_KEY", ""),
			TLSInsecure:          getBool("NATS_TLS_INSECURE", false),
			ReconnectWait:        getDuration("NATS_RECONNECT_WAIT", 2*time.Second),
			MaxReconnects:        getInt("NATS_MAX_RECONNECTS", -1),
			RequestTimeout:       getDuration("NATS_REQUEST_TIMEOUT", 5*time.Second),
			PublishRetryAttempts: getInt("NATS_PUBLISH_RETRY_ATTEMPTS", 3),
			PublishRetryDelay:    getDuration("NATS_PUBLISH_RETRY_DELAY", 200*time.Millisecond),
			DedupWindow:          getDuration("NATS_DEDUP_WINDOW", 2*time.Minute),
			Replicas:             getInt("NATS_REPLICAS", 1),
			Storage:              getStr("NATS_STORAGE", "file"),
			FetchBatchSize:       getInt("NATS_FETCH_BATCH_SIZE", 50),
			FetchMaxWait:         getDuration("NATS_FETCH_MAX_WAIT", 200*time.Millisecond),
			StreamPrefix:         getStr("NATS_STREAM_PREFIX", "SNG"),
		},
		Postgres: Postgres{
			Host:            getStr("PG_HOST", "127.0.0.1"),
			Port:            getInt("PG_PORT", 5432),
			User:            getStr("PG_USER", "sng"),
			Password:        getStr("PG_PASSWORD", "sng"),
			Database:        getStr("PG_DATABASE", "sng"),
			SSLMode:         getStr("PG_SSLMODE", "disable"),
			MaxOpenConns:    getInt("PG_MAX_OPEN_CONNS", 20),
			MaxIdleConns:    getInt("PG_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getDuration("PG_CONN_MAX_LIFETIME", time.Hour),
			ConnTimeout:     getDuration("PG_CONN_TIMEOUT", 5*time.Second),
			AppRole:         getStr("PG_APP_ROLE", "sng_app"),
		},
		RateLimit: RateLimit{
			Enabled:         getBool("RATE_LIMIT_ENABLED", true),
			Rate:            getFloat("RATE_LIMIT_RATE", 30.0),
			Burst:           getInt("RATE_LIMIT_BURST", 60),
			CleanupInterval: getDuration("RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("RATE_LIMIT_IDLE_TTL", 10*time.Minute),
			TrustedProxies:  getStr("RATE_LIMIT_TRUSTED_PROXIES", ""),
		},
		CORS: CORS{
			AllowedOrigins: parseCSV(getStr("CORS_ALLOWED_ORIGINS", "")),
			AllowedMethods: parseCSV(getStr("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")),
			AllowedHeaders: parseCSV(getStr("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Request-ID,X-SNG-API-Key")),
			MaxAge:         getDuration("CORS_MAX_AGE", time.Hour),
		},
		Webhook: Webhook{
			MaxRetries:      getInt("WEBHOOK_MAX_RETRIES", 6),
			InitialDelay:    getDuration("WEBHOOK_INITIAL_DELAY", time.Second),
			MaxDelay:        getDuration("WEBHOOK_MAX_DELAY", 5*time.Minute),
			DeliveryTimeout: getDuration("WEBHOOK_DELIVERY_TIMEOUT", 10*time.Second),
			SignatureHeader: getStr("WEBHOOK_SIGNATURE_HEADER", "X-SNG-Signature"),
		},
		Auth: Auth{
			JWTSecret:      getStr("AUTH_JWT_SECRET", ""),
			JWTIssuer:      getStr("AUTH_JWT_ISSUER", "sng-control"),
			JWTAudience:    getStr("AUTH_JWT_AUDIENCE", "sng-control"),
			AccessTokenTTL: getDuration("AUTH_ACCESS_TOKEN_TTL", time.Hour),
			APIKeyHeader:   getStr("AUTH_API_KEY_HEADER", "X-SNG-API-Key"),
		},
		Telemetry: Telemetry{
			OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceVersion: getStr("SERVICE_VERSION", ""),
		},
	}

	// Critical numeric settings: re-parse with the strict helpers so
	// a typo (e.g. HTTP_PORT="80a", HTTP_READ_TIMEOUT="5second")
	// fails boot loudly instead of silently reverting to the
	// default and giving us a wildly wrong setting in production.
	var strictErrs []error
	if v, err := getIntStrict("HTTP_PORT", 8080); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.HTTP.Port = v
	}
	if v, err := getDurationStrict("HTTP_READ_TIMEOUT", 15*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.HTTP.ReadTimeout = v
	}
	if v, err := getDurationStrict("HTTP_READ_HEADER_TIMEOUT", 5*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.HTTP.ReadHeaderTimeout = v
	}
	if v, err := getDurationStrict("HTTP_WRITE_TIMEOUT", 30*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.HTTP.WriteTimeout = v
	}
	if v, err := getIntStrict("PG_PORT", 5432); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Postgres.Port = v
	}
	if v, err := getIntStrict("PG_MAX_OPEN_CONNS", 20); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Postgres.MaxOpenConns = v
	}
	if v, err := getDurationStrict("PG_CONN_TIMEOUT", 5*time.Second); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Postgres.ConnTimeout = v
	}
	if v, err := getIntStrict("WEBHOOK_MAX_RETRIES", 6); err != nil {
		strictErrs = append(strictErrs, err)
	} else {
		cfg.Webhook.MaxRetries = v
	}
	if len(strictErrs) > 0 {
		return cfg, errors.Join(strictErrs...)
	}

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// MustLoad calls [Load] and panics on error. Useful in main() only.
func MustLoad() Config {
	cfg, err := Load()
	if err != nil {
		panic(err)
	}
	return cfg
}

// validate enforces minimal correctness invariants.
func (c Config) validate() error {
	if c.AppName == "" {
		return errors.New("APP_NAME must be set")
	}
	if !c.Environment.Valid() {
		return fmt.Errorf("ENVIRONMENT: invalid value %q (expected local|dev|qa|uat|prod)", c.Environment)
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP_PORT out of range: %d", c.HTTP.Port)
	}
	if c.HTTP.ReadTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_TIMEOUT must be > 0, got %s", c.HTTP.ReadTimeout)
	}
	if c.HTTP.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT must be > 0, got %s", c.HTTP.ReadHeaderTimeout)
	}
	if c.HTTP.WriteTimeout <= 0 {
		return fmt.Errorf("HTTP_WRITE_TIMEOUT must be > 0, got %s", c.HTTP.WriteTimeout)
	}
	// HTTP_READ_HEADER_TIMEOUT must be <= HTTP_READ_TIMEOUT.
	// Otherwise the header-read deadline never fires (the body-read
	// deadline always wins), defeating its Slowloris-mitigation
	// purpose.
	if c.HTTP.ReadHeaderTimeout > c.HTTP.ReadTimeout {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT (%s) must be <= HTTP_READ_TIMEOUT (%s)",
			c.HTTP.ReadHeaderTimeout, c.HTTP.ReadTimeout)
	}
	if c.HTTP.ShutdownTimeout <= 0 {
		return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be > 0, got %s", c.HTTP.ShutdownTimeout)
	}
	if c.Postgres.Port <= 0 || c.Postgres.Port > 65535 {
		return fmt.Errorf("PG_PORT out of range: %d", c.Postgres.Port)
	}
	if c.Postgres.Host == "" {
		return errors.New("PG_HOST must be set")
	}
	if c.Postgres.Database == "" {
		return errors.New("PG_DATABASE must be set")
	}
	if c.Postgres.User == "" {
		return errors.New("PG_USER must be set")
	}
	// Connection-pool sizes are stored as Go int because env parsing
	// is via strconv.Atoi, but the pgx driver takes int32. Bound the
	// configured values so a typo like PG_MAX_OPEN_CONNS=2147483648
	// fails boot rather than wrapping to a negative number.
	if c.Postgres.MaxOpenConns < 1 || c.Postgres.MaxOpenConns > 10_000 {
		return fmt.Errorf("PG_MAX_OPEN_CONNS out of range [1,10000]: %d", c.Postgres.MaxOpenConns)
	}
	if c.Postgres.MaxIdleConns < 0 || c.Postgres.MaxIdleConns > c.Postgres.MaxOpenConns {
		return fmt.Errorf("PG_MAX_IDLE_CONNS out of range [0,%d]: %d", c.Postgres.MaxOpenConns, c.Postgres.MaxIdleConns)
	}
	switch c.Postgres.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("PG_SSLMODE: invalid value %q", c.Postgres.SSLMode)
	}
	if c.NATS.URL == "" {
		return errors.New("NATS_URL must be set")
	}
	if c.NATS.PublishRetryAttempts < 0 {
		return fmt.Errorf("NATS_PUBLISH_RETRY_ATTEMPTS must be >= 0, got %d", c.NATS.PublishRetryAttempts)
	}
	switch c.NATS.Storage {
	case "file", "memory":
	default:
		return fmt.Errorf("NATS_STORAGE: invalid value %q (expected file|memory)", c.NATS.Storage)
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Rate <= 0 {
			return fmt.Errorf("RATE_LIMIT_RATE must be > 0 when enabled, got %v", c.RateLimit.Rate)
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("RATE_LIMIT_BURST must be > 0 when enabled, got %d", c.RateLimit.Burst)
		}
	}
	if c.Webhook.MaxRetries < 0 {
		return fmt.Errorf("WEBHOOK_MAX_RETRIES must be >= 0, got %d", c.Webhook.MaxRetries)
	}
	if c.Webhook.InitialDelay <= 0 {
		return fmt.Errorf("WEBHOOK_INITIAL_DELAY must be > 0, got %s", c.Webhook.InitialDelay)
	}
	if c.Webhook.MaxDelay < c.Webhook.InitialDelay {
		return fmt.Errorf("WEBHOOK_MAX_DELAY (%s) must be >= WEBHOOK_INITIAL_DELAY (%s)", c.Webhook.MaxDelay, c.Webhook.InitialDelay)
	}
	if c.Auth.JWTSecret == "" && c.Environment.IsProduction() {
		return errors.New("AUTH_JWT_SECRET must be set in production environments")
	}
	if c.Environment.IsProduction() && c.NATS.TLSInsecure {
		return errors.New("NATS_TLS_INSECURE must be false in production environments")
	}
	if c.Environment.IsProduction() && c.Postgres.SSLMode == "disable" {
		return errors.New("PG_SSLMODE must not be 'disable' in production environments")
	}
	return nil
}

// --- env helpers ------------------------------------------------------------

func getStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

// getIntStrict is the variant of getInt used for critical settings
// where a typo or stray whitespace must fail boot rather than
// silently fall back to a default that may differ from the
// operator's intent.
func getIntStrict(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, v, err)
	}
	return n, nil
}

// getDurationStrict is the duration twin of getIntStrict.
func getDurationStrict(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

// parseCSV splits a comma-separated list into a trimmed slice. Empty
// fields are dropped so trailing or duplicate commas do not produce
// empty allow-list entries.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadDotEnv parses a minimal .env file and assigns variables that
// aren't already in the process environment. Lines beginning with
// `#` and blank lines are ignored. Values may be optionally quoted.
//
// This is intentionally tiny: production deployments should source
// the environment from the orchestrator (k8s ConfigMap/Secret, ECS
// env, etc.).
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[0] == val[len(val)-1] {
			val = val[1 : len(val)-1]
		}
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return nil
}
