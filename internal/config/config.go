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
	"net/url"
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
	URL           string
	Name          string
	User          string
	Password      string
	Token         string
	CredsFile     string
	TLSCAFile     string
	TLSCertFile   string
	TLSKeyFile    string
	TLSInsecure   bool
	ReconnectWait time.Duration
	MaxReconnects int
	// ConnectTimeout is the dial timeout for the initial TCP / TLS
	// handshake against the NATS server, mapped to nats.Timeout().
	// Defaults to 5s and is intentionally separate from
	// RequestTimeout so operators can tune dial latency budgets
	// without affecting per-request deadlines.
	ConnectTimeout time.Duration
	// RequestTimeout is the per-request deadline used for
	// JetStream request-reply calls (nats.Conn.RequestWithContext,
	// nats.JetStream PublishOpts, etc.). It is NOT used for the
	// initial connection dial — that is ConnectTimeout. Defaults
	// to 5s.
	RequestTimeout       time.Duration
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration
	DedupWindow          time.Duration
	Replicas             int
	Storage              string // "file" or "memory"
	FetchBatchSize       int
	FetchMaxWait         time.Duration
	// StreamPrefix is prepended to every JetStream stream name
	// (e.g. "SNG_TELEMETRY"). It isolates *stream names* only;
	// subject patterns (`sng.*.telemetry.>`, etc.) are hard-coded
	// and NOT parameterised by prefix. To run multiple SNG control
	// planes on the same NATS infrastructure, deploy each in its
	// own JetStream domain or NATS account — StreamPrefix is then
	// a readability aid for telling stream names apart across
	// domains, not a multi-tenancy primitive on a shared account.
	// See `nats.DefaultStreams` for the exact subject patterns and
	// why overlap rejection in JetStream makes single-account
	// sharing impractical. Defaults to "SNG".
	StreamPrefix string
}

// Postgres carries database connection config.
type Postgres struct {
	Host         string
	Port         int
	User         string
	Password     string
	Database     string
	SSLMode      string
	MaxOpenConns int
	// MinConns is the **floor** on the pgxpool connection pool — the
	// pool eagerly creates and maintains at least this many
	// connections in the background. This is **NOT** the
	// database/sql `MaxIdleConns` ceiling: pgxpool does not expose an
	// idle-connection ceiling, instead retiring excess connections
	// after `MaxConnIdleTime`. We deliberately name the field
	// `MinConns` and the env var `PG_MIN_CONNS` to match the pgx
	// semantic so an operator setting `PG_MIN_CONNS=5` gets the
	// floor they're asking for, not the inverted ceiling implied by
	// the older `PG_MAX_IDLE_CONNS` name.
	MinConns        int
	ConnMaxLifetime time.Duration
	ConnTimeout     time.Duration
	// AppRole is the Postgres role the application connects as
	// (defaults to the connection user). Reserved for future
	// privilege-separation: control-plane RLS policies grant
	// SELECT/INSERT/UPDATE on tenant-scoped tables to this role
	// only.
	AppRole string
}

// MigrationURL returns a `pgx5://` URL suitable for passing to
// golang-migrate/v4's pgx/v5 database driver.
//
// The migrate library uses URL parsing (net/url) rather than libpq
// keyword/value strings, so we render the components with the
// standard `userinfo@host:port/dbname?query` shape and let
// `url.URL.String()` percent-escape any awkward characters. SSL mode
// and connect timeout are carried as query parameters; the latter
// is documented by golang-migrate as `x-connect-timeout`.
func (p Postgres) MigrationURL() string {
	u := url.URL{
		Scheme: "pgx5",
		User:   url.UserPassword(p.User, p.Password),
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:   "/" + p.Database,
	}
	q := u.Query()
	if p.SSLMode != "" {
		q.Set("sslmode", p.SSLMode)
	}
	if p.ConnTimeout > 0 {
		q.Set("connect_timeout", strconv.Itoa(connectTimeoutSeconds(p.ConnTimeout)))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// DSN returns a libpq keyword/value connection string.
//
// Values containing spaces, backslashes or single-quotes are
// single-quoted per the libpq syntax so a password like
// `my secret'pass\` is parsed correctly by pgxpool.ParseConfig
// instead of producing a confusing boot-time error.
//
// libpq keyword/value rules (per the official spec):
//   - Empty values must be written as ”.
//   - Values containing whitespace or single quotes must be quoted.
//   - Within single quotes, single quotes and backslashes are
//     escaped with a leading backslash.
func (p Postgres) DSN() string {
	var b strings.Builder
	writePair := func(k, v string) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(libpqQuote(v))
	}
	writePair("host", p.Host)
	writePair("port", strconv.Itoa(p.Port))
	writePair("user", p.User)
	writePair("password", p.Password)
	writePair("dbname", p.Database)
	writePair("sslmode", p.SSLMode)
	writePair("connect_timeout", strconv.Itoa(connectTimeoutSeconds(p.ConnTimeout)))
	return b.String()
}

// connectTimeoutSeconds renders ConnTimeout as the integer-seconds value
// libpq expects for connect_timeout. libpq treats `connect_timeout=0`
// as "wait indefinitely", so any positive sub-second duration must be
// rounded up to 1s rather than truncated to 0 — otherwise an operator
// who sets PG_CONN_TIMEOUT=500ms ends up with a libpq connect path
// that never times out. Non-positive values are written as 0
// explicitly (libpq's documented "infinite" semantic); validate() in
// turn rejects ConnTimeout <= 0 so this branch is unreachable from
// Load() but covers manually-constructed configs.
func connectTimeoutSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	s := int(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return s
}

// libpqQuote returns a libpq keyword/value-safe rendering of v.
//
// libpq's parser accepts unquoted values only when they contain no
// whitespace, backslashes, or single-quotes. Anything outside that
// safe set — plus empty strings — must be wrapped in single quotes,
// with backslash and single-quote within escaped by a leading
// backslash. See:
//
//	https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-KEYWORD-VALUE
func libpqQuote(v string) string {
	if v == "" {
		return "''"
	}
	needsQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\\' || c == '\'' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	b.WriteByte('\'')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' || c == '\'' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('\'')
	return b.String()
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
		// Non-load-bearing fields parsed leniently (defaults are safe
		// on typo). Load-bearing numeric fields (ports, timeouts,
		// pool sizes, retry budgets, rate-limit knobs) are NOT set
		// here — they're populated by the strictInts / strictDurations /
		// strictFloats tables below so the strict tables are the
		// single source of truth for both the default and the env
		// var name. This eliminates the dual-parse subtlety where
		// a new strict-worthy field could be added to the lenient
		// block and silently fall back to the default on typo.
		HTTP: HTTP{
			Host: getStr("HTTP_HOST", "0.0.0.0"),
		},
		NATS: NATS{
			URL:          getStr("NATS_URL", "nats://127.0.0.1:4222"),
			Name:         getStr("NATS_NAME", "sng-control"),
			User:         getStr("NATS_USER", ""),
			Password:     getStr("NATS_PASSWORD", ""),
			Token:        getStr("NATS_TOKEN", ""),
			CredsFile:    getStr("NATS_CREDS_FILE", ""),
			TLSCAFile:    getStr("NATS_TLS_CA", ""),
			TLSCertFile:  getStr("NATS_TLS_CERT", ""),
			TLSKeyFile:   getStr("NATS_TLS_KEY", ""),
			Storage:      getStr("NATS_STORAGE", "file"),
			StreamPrefix: getStr("NATS_STREAM_PREFIX", "SNG"),
			// TLSInsecure is populated by the strictBools table below so
			// that a typo (NATS_TLS_INSECURE=yes) fails boot rather than
			// silently keeping the secure default — same single-source-of-
			// truth rule that governs strict ints / durations / floats.
		},
		Postgres: Postgres{
			Host:     getStr("PG_HOST", "127.0.0.1"),
			User:     getStr("PG_USER", "sng"),
			Password: getStr("PG_PASSWORD", "sng"),
			Database: getStr("PG_DATABASE", "sng"),
			SSLMode:  getStr("PG_SSLMODE", "disable"),
			AppRole:  getStr("PG_APP_ROLE", "sng_app"),
		},
		RateLimit: RateLimit{
			CleanupInterval: getDuration("RATE_LIMIT_CLEANUP_INTERVAL", time.Minute),
			IdleTTL:         getDuration("RATE_LIMIT_IDLE_TTL", 10*time.Minute),
			TrustedProxies:  getStr("RATE_LIMIT_TRUSTED_PROXIES", ""),
			// Enabled is populated by the strictBools table below.
		},
		CORS: CORS{
			AllowedOrigins: parseCSV(getStr("CORS_ALLOWED_ORIGINS", "")),
			AllowedMethods: parseCSV(getStr("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")),
			AllowedHeaders: parseCSV(getStr("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Request-ID,X-SNG-API-Key")),
			MaxAge:         getDuration("CORS_MAX_AGE", time.Hour),
		},
		Webhook: Webhook{
			SignatureHeader: getStr("WEBHOOK_SIGNATURE_HEADER", "X-SNG-Signature"),
		},
		Auth: Auth{
			JWTSecret:    getStr("AUTH_JWT_SECRET", ""),
			JWTIssuer:    getStr("AUTH_JWT_ISSUER", "sng-control"),
			JWTAudience:  getStr("AUTH_JWT_AUDIENCE", "sng-control"),
			APIKeyHeader: getStr("AUTH_API_KEY_HEADER", "X-SNG-API-Key"),
		},
		Telemetry: Telemetry{
			OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceVersion: getStr("SERVICE_VERSION", ""),
		},
	}

	// Critical numeric settings: re-parse with the strict helpers
	// so a typo (e.g. HTTP_PORT="80a", HTTP_READ_TIMEOUT="5second")
	// fails boot loudly instead of silently reverting to the default
	// and giving us a wildly wrong setting in production.
	//
	// Strict parsing is reserved for fields where silently using the
	// default could mask a security or correctness regression
	// (timeouts, ports, retry budgets, pool sizes, rate limits,
	// dedup windows). Lenient parsing is intentionally retained for
	// purely cosmetic / non-load-bearing fields where defaults are
	// always safe.
	strictInts := []struct {
		key string
		def int
		dst *int
	}{
		{"HTTP_PORT", 8080, &cfg.HTTP.Port},
		{"PG_PORT", 5432, &cfg.Postgres.Port},
		{"PG_MAX_OPEN_CONNS", 20, &cfg.Postgres.MaxOpenConns},
		{"PG_MIN_CONNS", 2, &cfg.Postgres.MinConns},
		{"NATS_MAX_RECONNECTS", -1, &cfg.NATS.MaxReconnects},
		{"NATS_REPLICAS", 1, &cfg.NATS.Replicas},
		{"NATS_FETCH_BATCH_SIZE", 50, &cfg.NATS.FetchBatchSize},
		{"NATS_PUBLISH_RETRY_ATTEMPTS", 3, &cfg.NATS.PublishRetryAttempts},
		{"RATE_LIMIT_BURST", 60, &cfg.RateLimit.Burst},
		{"WEBHOOK_MAX_RETRIES", 6, &cfg.Webhook.MaxRetries},
	}
	strictDurations := []struct {
		key string
		def time.Duration
		dst *time.Duration
	}{
		{"HTTP_READ_TIMEOUT", 15 * time.Second, &cfg.HTTP.ReadTimeout},
		{"HTTP_READ_HEADER_TIMEOUT", 5 * time.Second, &cfg.HTTP.ReadHeaderTimeout},
		{"HTTP_WRITE_TIMEOUT", 30 * time.Second, &cfg.HTTP.WriteTimeout},
		{"HTTP_SHUTDOWN_TIMEOUT", 10 * time.Second, &cfg.HTTP.ShutdownTimeout},
		{"PG_CONN_TIMEOUT", 5 * time.Second, &cfg.Postgres.ConnTimeout},
		{"PG_CONN_MAX_LIFETIME", time.Hour, &cfg.Postgres.ConnMaxLifetime},
		{"NATS_CONNECT_TIMEOUT", 5 * time.Second, &cfg.NATS.ConnectTimeout},
		{"NATS_REQUEST_TIMEOUT", 5 * time.Second, &cfg.NATS.RequestTimeout},
		{"NATS_RECONNECT_WAIT", 2 * time.Second, &cfg.NATS.ReconnectWait},
		{"NATS_DEDUP_WINDOW", 2 * time.Minute, &cfg.NATS.DedupWindow},
		{"NATS_PUBLISH_RETRY_DELAY", 200 * time.Millisecond, &cfg.NATS.PublishRetryDelay},
		{"NATS_FETCH_MAX_WAIT", 200 * time.Millisecond, &cfg.NATS.FetchMaxWait},
		{"WEBHOOK_INITIAL_DELAY", time.Second, &cfg.Webhook.InitialDelay},
		{"WEBHOOK_MAX_DELAY", 5 * time.Minute, &cfg.Webhook.MaxDelay},
		{"WEBHOOK_DELIVERY_TIMEOUT", 10 * time.Second, &cfg.Webhook.DeliveryTimeout},
		{"AUTH_ACCESS_TOKEN_TTL", time.Hour, &cfg.Auth.AccessTokenTTL},
	}
	strictFloats := []struct {
		key string
		def float64
		dst *float64
	}{
		{"RATE_LIMIT_RATE", 30.0, &cfg.RateLimit.Rate},
	}
	// Boolean fields parsed strictly. Both entries below toggle
	// security- or correctness-adjacent behaviour:
	//   - NATS_TLS_INSECURE skips TLS verification (CA pinning is the
	//     whole point of that field), so an operator-intended
	//     "true" that lands here as the default "false" silently
	//     leaves the connection unverified — and the inverse silently
	//     leaves a self-signed dev cluster broken. Both are bad.
	//   - RATE_LIMIT_ENABLED gates the rate-limit middleware. An
	//     operator-intended "false" (load test, debug) that lands as
	//     the default "true" silently denies traffic; the inverse
	//     silently disables protection.
	// Fail boot on any value strconv.ParseBool refuses so the
	// operator's intent is never silently overridden by a default.
	strictBools := []struct {
		key string
		def bool
		dst *bool
	}{
		{"NATS_TLS_INSECURE", false, &cfg.NATS.TLSInsecure},
		{"RATE_LIMIT_ENABLED", true, &cfg.RateLimit.Enabled},
	}

	var strictErrs []error
	for _, s := range strictInts {
		v, err := getIntStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictDurations {
		v, err := getDurationStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictFloats {
		v, err := getFloatStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
	}
	for _, s := range strictBools {
		v, err := getBoolStrict(s.key, s.def)
		if err != nil {
			strictErrs = append(strictErrs, err)
			continue
		}
		*s.dst = v
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
	// libpq's connect_timeout DSN field is rendered as integer seconds
	// (ceil for sub-second values), and libpq treats 0 as "infinite".
	// Reject non-positive durations here so neither the libpq fallback
	// nor the pgx dial path can race to infinity behind an operator's
	// back.
	if c.Postgres.ConnTimeout <= 0 {
		return fmt.Errorf("PG_CONN_TIMEOUT must be > 0, got %s", c.Postgres.ConnTimeout)
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
	// PG_MIN_CONNS is the floor on idle connections eagerly
	// maintained by pgxpool. It must be in [0, PG_MAX_OPEN_CONNS]:
	// MinConns > MaxConns would deadlock the pool acquire loop.
	if c.Postgres.MinConns < 0 || c.Postgres.MinConns > c.Postgres.MaxOpenConns {
		return fmt.Errorf("PG_MIN_CONNS out of range [0,%d]: %d", c.Postgres.MaxOpenConns, c.Postgres.MinConns)
	}
	switch c.Postgres.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("PG_SSLMODE: invalid value %q", c.Postgres.SSLMode)
	}
	if c.NATS.URL == "" {
		return errors.New("NATS_URL must be set")
	}
	// NATS_PUBLISH_RETRY_ATTEMPTS is the total publish attempt budget
	// (first try + retries). The publisher's fallback chain
	// (opts.MaxAttempts → opts.MaxRetries → cfg.PublishRetryAttempts →
	// hard-coded 3) uses `<= 0` as the "unset, fall through" sentinel
	// at every level. Allowing 0 here would mean operators who
	// explicitly set 0 to express "single attempt, no retries" would
	// silently get the hard-coded default of 3 instead — their
	// configuration ignored. Require >= 1 so the validator and the
	// publisher agree on what "set" means. Operators wanting a single
	// attempt set this to 1.
	if c.NATS.PublishRetryAttempts < 1 {
		return fmt.Errorf("NATS_PUBLISH_RETRY_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.NATS.PublishRetryAttempts)
	}
	// NATS_CONNECT_TIMEOUT is wired to nats.Timeout() for the initial
	// dial. The nats.go client treats 0 as "no deadline" — the dial
	// will block forever waiting on a flapping server — so we reject
	// it here to match the operator's almost-certain intent.
	if c.NATS.ConnectTimeout <= 0 {
		return fmt.Errorf("NATS_CONNECT_TIMEOUT must be > 0, got %s", c.NATS.ConnectTimeout)
	}
	// NATS_REQUEST_TIMEOUT is the per-request deadline used by
	// nats.Conn.RequestWithContext and JetStream Publish opts. A zero
	// value gives an infinite request deadline; same reason as above.
	if c.NATS.RequestTimeout <= 0 {
		return fmt.Errorf("NATS_REQUEST_TIMEOUT must be > 0, got %s", c.NATS.RequestTimeout)
	}
	// NATS_DEDUP_WINDOW: zero is explicitly NOT rejected, but its
	// runtime meaning is "use the JetStream server default
	// (~2 minutes)", NOT "disabled". JetStream's `Duplicates`
	// field treats 0 as "absent → server default", and the
	// nats-server team has not exposed a true off-switch. Our
	// `DefaultStreams` wrapper folds `<=0` into the same 2m
	// default for consistency. Operators who want a different
	// window must set a positive duration; there is no "disabled"
	// option today (a follow-up could route true-disable via a
	// sentinel like -1, but no caller currently needs that).
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
	// WEBHOOK_DELIVERY_TIMEOUT is mapped to the per-attempt
	// http.Client.Timeout. Go's net/http treats 0 as "no timeout",
	// which against an unresponsive subscriber would pin a worker
	// goroutine + connection indefinitely and exhaust the delivery
	// pool. Reject 0 explicitly so the strict parser's 0s acceptance
	// can't slip through.
	if c.Webhook.DeliveryTimeout <= 0 {
		return fmt.Errorf("WEBHOOK_DELIVERY_TIMEOUT must be > 0, got %s", c.Webhook.DeliveryTimeout)
	}
	// AUTH_ACCESS_TOKEN_TTL <= 0 makes every issued token already
	// expired, which would silently lock every operator out of the
	// console. Forbid here so the strict parser's lenient acceptance
	// of "0s" is caught at boot rather than at first sign-in.
	if c.Auth.AccessTokenTTL <= 0 {
		return fmt.Errorf("AUTH_ACCESS_TOKEN_TTL must be > 0, got %s", c.Auth.AccessTokenTTL)
	}
	if c.Auth.JWTSecret == "" && c.Environment.IsProduction() {
		return errors.New("AUTH_JWT_SECRET must be set in production environments")
	}
	if c.Environment.IsProduction() && c.NATS.TLSInsecure {
		return errors.New("NATS_TLS_INSECURE must be false in production environments")
	}
	if c.Environment.IsProduction() {
		// In production we require a sslmode that guarantees TLS.
		// `disable` is unencrypted; `allow` attempts plaintext
		// first and only upgrades if the server insists; `prefer`
		// attempts TLS but silently falls back to plaintext if
		// TLS fails. Only `require`, `verify-ca`, and
		// `verify-full` provide a hard guarantee that the
		// connection is encrypted (verify-ca / verify-full also
		// authenticate the server). The validator runs after the
		// generic enum whitelist above, so any value reaching
		// here is already a recognised mode.
		switch c.Postgres.SSLMode {
		case "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("PG_SSLMODE must be one of require|verify-ca|verify-full in production environments, got %q", c.Postgres.SSLMode)
		}
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

// getIntStrict is the only int-parsing helper exposed by this
// package: every int-valued setting is critical enough that a typo
// must fail boot rather than silently fall back to a default that
// may differ from the operator's intent.
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

// getFloatStrict is the float64 twin of getIntStrict.
func getFloatStrict(key string, def float64) (float64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid float: %w", key, v, err)
	}
	return f, nil
}

// getBoolStrict is the bool twin of getIntStrict. We deliberately
// do not ship a lenient getBool helper: every boolean field consumed
// by Load() is either security-adjacent (e.g. NATS_TLS_INSECURE) or
// gates a load-bearing middleware (e.g. RATE_LIMIT_ENABLED), so a
// silent fall-back to the default on a typo like
// NATS_TLS_INSECURE=yes could mask the operator's intent in either
// direction. strconv.ParseBool already accepts the documented set
// {1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False} — any
// value outside that set is a config error, not a "be lenient" case.
func getBoolStrict(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s=%q is not a valid boolean (accepted: true/false/1/0): %w", key, v, err)
	}
	return b, nil
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
// aren't already in the process environment. The format mirrors the
// de-facto conventions used by docker-compose / direnv:
//
//   - Lines beginning with `#` and blank lines are ignored.
//   - Lines may optionally start with the shell `export` keyword,
//     which is stripped before parsing.
//   - Values may be optionally quoted with single or double quotes,
//     in which case the quotes are stripped.
//   - In unquoted values, an unescaped `#` introduces a trailing
//     comment that is stripped. Within quoted values `#` is taken
//     literally so passwords containing `#` survive.
//
// This is intentionally tiny: production deployments should source
// the environment from the orchestrator (k8s ConfigMap/Secret, ECS
// env, etc.). The `.env` loader exists only so that local-dev and
// CI scripts can drop their config in one place.
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow `export FOO=bar` for ergonomic copy-paste from a
		// shell session. The "export " prefix is stripped before
		// the key is parsed; "exportFOO=bar" is NOT treated as
		// an export and remains literal.
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimPrefix(line, "export\t")
		line = strings.TrimLeft(line, " \t")

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		switch {
		case len(val) >= 2 && (val[0] == '"' || val[0] == '\''):
			// Quoted-value path: take everything up to the
			// matching closing quote, then discard a trailing
			// `# comment` after the close. Anything inside the
			// quotes — including `#` — is preserved verbatim.
			quote := val[0]
			if end := strings.IndexByte(val[1:], quote); end >= 0 {
				rest := strings.TrimSpace(val[end+2:])
				if rest == "" || strings.HasPrefix(rest, "#") {
					val = val[1 : end+1]
				}
			}
		default:
			// Unquoted-value path: strip trailing `# comment`
			// only when preceded by whitespace, so a value
			// like `secret#1` survives but `secret # note`
			// becomes `secret`.
			if i := strings.IndexByte(val, '#'); i > 0 && (val[i-1] == ' ' || val[i-1] == '\t') {
				val = strings.TrimRight(val[:i], " \t")
			}
		}

		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return nil
}
