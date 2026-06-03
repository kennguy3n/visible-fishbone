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

	Log                Log
	HTTP               HTTP
	NATS               NATS
	Postgres           Postgres
	RateLimit          RateLimit
	CORS               CORS
	Webhook            Webhook
	Integration        Integration
	Auth               Auth
	Policy             Policy
	Telemetry          Telemetry
	TelemetryAnalytics TelemetryAnalytics
	AppRegistry        AppRegistry
	AI                 AI
	MobileAuth         MobileAuth
}

// MobileAuth carries the runtime knobs for control-plane IdP
// federation — the mobile native-SSO flow where a mobile agent
// presents an OIDC ID token and the control plane exchanges it for
// an SNG session bound to device + user identity (see
// internal/service/identity/oidc.go).
type MobileAuth struct {
	// SessionTokenTTL is how long a minted SNG mobile session token
	// is valid. Independent of Auth.AccessTokenTTL so operators can
	// give mobile sessions a different (typically shorter) lifetime
	// than operator-console tokens. Defaults to 1h.
	SessionTokenTTL time.Duration
	// DiscoveryCacheTTL is how long an OIDC discovery document (and
	// its JWKS) is cached per issuer before re-fetching. Defaults to
	// 24h, matching the OIDC ecosystem's typical key-rotation window.
	DiscoveryCacheTTL time.Duration
	// MaxProvidersPerTenant caps how many IdP configs a single tenant
	// may register. Defaults to 10. The handler enforces this at
	// create time.
	MaxProvidersPerTenant int
	// AutoProvisionUsers controls just-in-time user provisioning: when
	// a validated ID token maps to an email with no existing user in
	// the tenant, the OIDCService creates one (reusing the SCIM user
	// shape). Defaults to true. Set false to require users be
	// pre-provisioned (e.g. via SCIM) before they can federate.
	AutoProvisionUsers bool
}

// AppRegistry carries the runtime knobs for the curated
// app-classification engine. The Syncer pulls vendor-published
// endpoint lists (Microsoft 365, Google IP ranges, AWS, etc.) on
// a periodic schedule; SyncEnabled gates the background loop and
// SyncInterval sets its cadence. Both default to "on" with a
// 24-hour cadence so a fresh deployment behaves the way
// docs/TRAFFIC_CLASSIFICATION.md describes — operators do not
// have to set anything to get the periodic refresh. Set
// APP_REGISTRY_SYNC_ENABLED=false to disable (useful for local
// development, air-gapped clusters, and replicas that should not
// duplicate the primary's outbound vendor fetches).
type AppRegistry struct {
	// SyncEnabled toggles the periodic vendor-endpoint sync loop
	// in main(). When false, the admin-triggered
	// `POST /admin/app-registry/sync` endpoint still works — only
	// the background ticker is suppressed.
	SyncEnabled bool
	// SyncInterval is the cadence of the background sync loop.
	// Defaults to 24h. Anything <= 0 is treated as the default by
	// the Syncer; the strict parser still rejects un-parseable
	// values so an operator typo doesn't silently revert.
	SyncInterval time.Duration
}

// AI carries runtime knobs for the AI assistant service
// (Phase 3 Block 6). When Endpoint is empty the service runs in
// template-only mode — all summaries are deterministic and the
// suggest-policy / troubleshoot endpoints return 503.
type AI struct {
	Endpoint string
	APIKey   string
	Model    string
	Timeout  time.Duration
	// GuardrailMaxRequestsPerMinute is the per-tenant request rate
	// limit applied to every LLM-backed AI call. Defaults to 60.
	GuardrailMaxRequestsPerMinute int
	// GuardrailMaxTokensPerDay is the per-tenant daily token budget
	// for LLM-backed AI calls (cost control). Defaults to 100000.
	GuardrailMaxTokensPerDay int
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
	// Partitions is the number of telemetry stream cells the
	// control plane fans out across (env NATS_PARTITIONS, default
	// 1). At 1 the behaviour is identical to the historical
	// single-stream layout (`SNG_TELEMETRY`, subject
	// `sng.*.telemetry.>`). At N>1 the telemetry workload is
	// sharded into N cells `SNG_TELEMETRY_0`…`SNG_TELEMETRY_{N-1}`,
	// each scoped to a partition slot in the subject
	// (`sng.{partition}.*.telemetry.>`), so the control plane can
	// scale telemetry ingestion horizontally past the throughput
	// ceiling of a single JetStream stream. The owning tenant of an
	// event determines its partition via the consistent-hash
	// TenantPartitioner. validate() bounds this to [1, 256].
	Partitions int
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
	// AppRole is the PostgreSQL role the runtime adopts on every
	// new physical connection via `SET SESSION ROLE`. The login
	// user (PG_USER) authenticates the TCP connection; AppRole is
	// the role whose grants and RLS policies the application
	// actually exercises. See `docs/deploy.md` for the role-
	// separation architecture (`sng_app_login` → `sng_app`).
	//
	// Empty disables the SET SESSION ROLE hook: connections run
	// as PG_USER directly. This is intended ONLY for development
	// where a single PG_USER is granted DML directly; production
	// must always set PG_APP_ROLE (default: `sng_app`) so RLS
	// policies are enforced.
	AppRole string
	// ReadReplicaHosts is the comma-separated list of read-replica
	// hosts (env PG_READ_REPLICA_HOSTS). Empty disables the
	// read-write split — every query goes to the primary. When
	// populated, the repository layer routes read-only
	// transactions (List*/Get*/Count*, all `withTenantRO` paths)
	// to a healthy replica chosen round-robin, falling back to the
	// primary if every replica is unhealthy. RLS `set_config` runs
	// inside the replica transaction exactly as it does on the
	// primary, so tenant isolation is enforced on replicas too.
	ReadReplicaHosts []string
	// ReadReplicaPort is the TCP port the replicas listen on
	// (env PG_READ_REPLICA_PORT). 0 (the default) means "inherit
	// Port" — the common topology where every node listens on the
	// same port. validate() bounds a non-zero value to [1, 65535].
	ReadReplicaPort int
	// PgBouncerMode toggles transaction-pooling-safe behaviour
	// (env PG_PGBOUNCER_MODE). When false (default) the runtime
	// adopts AppRole once per physical connection via a
	// session-level `SET SESSION ROLE` (the AfterConnect hook).
	// That command is incompatible with a PgBouncer running in
	// transaction-pooling mode, where each transaction may land on
	// a different server-side connection and session state is
	// reset between transactions. When true, the session-level
	// hook is skipped and the repository layer instead issues a
	// transaction-local `SET LOCAL ROLE` at the top of every
	// tenant/system transaction, which is reverted on
	// commit/rollback and therefore safe under transaction
	// pooling.
	PgBouncerMode bool
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

// ReplicaPort returns the port read replicas listen on: the
// explicit ReadReplicaPort when set, otherwise the primary Port.
// Centralising the 0-means-inherit rule here keeps DSN rendering
// and validation in agreement.
func (p Postgres) ReplicaPort() int {
	if p.ReadReplicaPort > 0 {
		return p.ReadReplicaPort
	}
	return p.Port
}

// ReplicaDSN returns a libpq keyword/value connection string for a
// read replica reachable at `host`. It is identical to DSN() except
// the host and port are overridden with the replica endpoint
// (ReplicaPort): user, password, database, sslmode, and
// connect_timeout are inherited from the primary so a replica is
// authenticated and TLS-protected exactly like the primary. The
// AppRole / RLS posture is applied by the pool layer (AfterConnect
// in session mode, SET LOCAL ROLE in PgBouncer mode), not the DSN.
func (p Postgres) ReplicaDSN(host string) string {
	rp := p
	rp.Host = host
	rp.Port = p.ReplicaPort()
	return rp.DSN()
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

// Webhook holds outbound webhook delivery configuration. These
// values feed directly into the webhook.WorkerConfig at
// buildRouter time, so the operator's environment-variable knobs
// reach the live worker rather than the worker silently running on
// its compiled-in defaults (the PR6 review observed the previous
// wiring passed a zero-valued WorkerConfig).
type Webhook struct {
	// MaxAttempts is the TOTAL number of delivery attempts (first
	// try + retries) before a webhook is marked exhausted. Default
	// 6 — i.e. 1 initial delivery + 5 retries. Operators wanting a
	// single attempt with no retries set this to 1. Named
	// `MaxAttempts` (env `WEBHOOK_MAX_ATTEMPTS`) to match the
	// worker.WorkerConfig.MaxAttempts semantic exactly; the older
	// `MaxRetries` name conflated "attempts" with "retries after
	// the first" and made off-by-one delivery counts likely. The
	// validator below requires >= 1 so the publisher's fallback
	// chain (which uses <= 0 as the "unset, fall through" sentinel)
	// cannot silently override an operator's explicit value.
	MaxAttempts int
	// InitialDelay is the first retry delay; subsequent delays are
	// exponentially backed off up to MaxDelay. Default 1s.
	InitialDelay time.Duration
	// MaxDelay is the per-attempt backoff ceiling. Default 5m.
	MaxDelay time.Duration
	// DeliveryTimeout is the per-attempt HTTP client timeout.
	// Default 10s.
	DeliveryTimeout time.Duration
	// BatchSize caps the number of pending deliveries the worker
	// fetches per scheduling tick. A larger value increases
	// throughput on a backlog; a smaller value reduces per-tick
	// latency for new deliveries when the queue is shallow.
	// Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending queue
	// when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
	// ProcessingTimeout is the stuck-row recovery window. A
	// worker that crashes mid-delivery leaves its claimed rows in
	// `status='processing'`; the next ListPending re-claims them
	// once their last_attempt_at is older than
	// `now - ProcessingTimeout`. Choose to be safely longer than
	// the worst-case in-flight delivery (DeliveryTimeout +
	// scheduler overhead): too short and a single slow upstream
	// causes the same delivery to be dispatched twice, too long
	// and a true crash stalls the queue for that duration.
	// Default 5m.
	ProcessingTimeout time.Duration
	// SignatureHeader is the HTTP header carrying the HMAC-SHA256
	// signature. Defaults to "X-SNG-Signature".
	SignatureHeader string
}

// Integration carries the operator-facing knobs for the
// integration delivery worker. Round-4 of Devin Review on PR #41
// (PR D) flagged that the worker was constructed with
// `integration.WorkerConfig{}` at cmd/sng-control/main.go:496 —
// the same `WorkerConfig{}` anti-pattern that the webhook worker
// originally shipped with. The previous wiring meant every field
// silently fell back to the hard-coded defaults in
// internal/service/integration/worker.go:46-65 (BatchSize=32,
// PollInterval=1s, MaxAttempts=8, BackoffBase=30s, BackoffMax=1h,
// ProcessingTimeout=5m) — operators exporting their tuning knobs
// would see the validator accept them at boot but the values
// would never reach the live worker. This struct mirrors the
// Webhook layout so the two delivery workers are uniformly
// tunable.
type Integration struct {
	// MaxAttempts is the TOTAL number of delivery attempts (first
	// try + retries) before a delivery is marked exhausted.
	// Default 8. Operators wanting a single attempt with no
	// retries set this to 1.
	MaxAttempts int
	// BackoffBase is the base factor for exponential backoff:
	// `next_retry = now + BackoffBase * 2^(attempt-1)`, capped at
	// `BackoffMax`. Default 30s.
	BackoffBase time.Duration
	// BackoffMax is the per-attempt backoff ceiling. Default 1h.
	BackoffMax time.Duration
	// ProcessingTimeout is the stuck-row recovery window. A
	// worker that crashes mid-delivery leaves its claimed rows
	// in `status='processing'`; the next ListPending re-claims
	// them once their last_attempt_at is older than
	// `now - ProcessingTimeout`. Choose to be safely longer than
	// the worst-case in-flight delivery so a true crash is
	// reclaimed but a slow upstream is not double-dispatched.
	// Default 5m.
	ProcessingTimeout time.Duration
	// BatchSize caps the number of pending deliveries the worker
	// fetches per scheduling tick. Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending
	// queue when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
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
	// ClaimTokenTTL is the default lifetime of a fresh one-time
	// device-enrollment claim token (POST /claim-tokens) when the
	// API caller does not specify ttl_seconds explicitly. This is
	// the operator's window to install the agent on the new device
	// and have it call /devices/enroll before the token expires;
	// shorter is more secure, longer reduces operator friction.
	// Defaults to 24h, must be > 0.
	ClaimTokenTTL time.Duration
	// APIKeyHeader is the HTTP header carrying API keys for
	// machine-to-machine authentication (defaults to
	// "X-SNG-API-Key").
	APIKeyHeader string
	// APIKeyMaxActivePerTenant caps the number of active
	// (non-revoked, non-expired) API keys a single tenant may
	// hold. The service enforces this at Create time. Defaults to
	// apikey.DefaultMaxActiveKeys (64). Set <= 0 to disable the
	// cap entirely (test fixtures only — production must keep a
	// finite cap, see validate()).
	APIKeyMaxActivePerTenant int
}

// Policy carries policy-engine configuration. PR8 adds two
// production-only knobs: a path to an out-of-band Ed25519 signing
// key (so prod can boot without DB-backed rotation) and an
// AES-256-GCM master key for at-rest wrapping of any DB-stored
// signing seeds (KMS-on-a-stick for deployments without a real
// KMS in the loop).
type Policy struct {
	// SigningKeyPath optionally points at a PEM / hex / raw
	// 32-byte file containing an Ed25519 private key. When set,
	// the policy service ignores the per-tenant DB-backed key
	// store and signs every bundle with this key — useful for
	// deployments where rotation is managed via configuration
	// management (CD pipeline replaces the file and restarts the
	// process) rather than online operator action. Mutually
	// exclusive with the DB rotation API for the active tenant
	// set.
	SigningKeyPath string
	// KeyWrapMasterB64 is a base64-encoded 32-byte AES-256 master
	// key used by the AESGCMWrapper to encrypt signing-key seeds
	// at rest in the policy_signing_keys.private_key column.
	// Mutually exclusive with KeyWrapMasterFile. Empty in both
	// places means PassthroughWrapper (plain seed on disk, at-rest
	// protection via TDE / disk encryption).
	KeyWrapMasterB64 string
	// KeyWrapMasterFile is a path to either 32 raw bytes or the
	// base64 encoding thereof. Mutually exclusive with B64.
	KeyWrapMasterFile string
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

// TelemetryAnalytics carries the wiring knobs for the hot-path
// (ClickHouse) and cold-path (S3) telemetry analytics sinks. The
// fields are independent: a deployment can enable ClickHouse
// without S3, S3 without ClickHouse, or both. Leaving every
// field empty disables both sinks — the consumer falls back to
// the no-op writers, which is the correct development default
// (the consumer loop, dedup, DLQ machinery all still run; only
// the long-term sinks are skipped).
type TelemetryAnalytics struct {
	// ClickHouse: comma-separated host:port list (native protocol
	// port 9000, secure native 9440). Empty disables the hot-path
	// sink.
	ClickHouseEndpoints []string
	// ClickHouseDatabase, ClickHouseTable scope the writer to a
	// specific database / table. Defaults: "default" / "sng_telemetry".
	ClickHouseDatabase string
	ClickHouseTable    string
	// ClickHouseUsername / Password authenticate against the
	// ClickHouse cluster. In production both must be supplied;
	// boot fails otherwise (see validate()).
	ClickHouseUsername string
	ClickHousePassword string
	// ClickHouseTLS enables the secure native protocol. The driver
	// uses the system root CA pool; a custom CA can be configured
	// via the SSL_CERT_FILE environment variable.
	ClickHouseTLS bool
	// ClickHouseFlushInterval / BatchSize tune the hot-path
	// buffering. Defaults: 2s, 1024 rows.
	ClickHouseFlushInterval time.Duration
	ClickHouseBatchSize     int
	// ClickHouseMaxBacklogMultiplier bounds how many
	// `ClickHouseBatchSize`-worth of rows the writer is willing
	// to retain in its in-memory shield across transient
	// ClickHouse outages. When the requeue path would push the
	// backlog past `BatchSize * MaxBacklogMultiplier`, the
	// OLDEST rows are shed (FIFO) and credited to BacklogDrops
	// + DroppedRows. Default 4 (≈ 8s of buffering at the 2s
	// default flush interval). Operators with tight memory
	// budgets or large batch sizes may want to lower this;
	// operators with bursty producers and a known-long
	// ClickHouse maintenance window may want to raise it.
	ClickHouseMaxBacklogMultiplier int
	// ClickHouseEnsureSchema controls whether the writer issues a
	// CREATE TABLE IF NOT EXISTS for the destination table on
	// boot. Defaults true; set false when the table is provisioned
	// out-of-band (e.g. dbt / Liquibase / a managed-service
	// provisioning workflow).
	ClickHouseEnsureSchema bool

	// ClickHouseSharding switches the hot-path writer from the
	// default single-cluster mode (where every endpoint in
	// CLICKHOUSE_ENDPOINTS is treated as an interchangeable
	// replica the driver load-balances across) to shard-aware
	// mode (env CLICKHOUSE_SHARDING). In shard-aware mode each
	// endpoint is a distinct ClickHouse shard and rows are routed
	// by a stable hash of tenant_id modulo the shard count, with
	// one independent Writer (its own batch buffer + flush loop)
	// per shard. This lifts the single-node ingest/storage ceiling
	// the platform hits past ~5,000 tenants. Cross-tenant operator
	// analytics fan out across all shards in parallel and merge.
	// Defaults false so existing single-cluster deployments are
	// unaffected; only meaningful when more than one endpoint is
	// configured (with a single endpoint the two modes are
	// identical).
	ClickHouseSharding bool

	// S3: bucket name. Empty disables the cold-path sink.
	S3Bucket string
	// S3Prefix is the top-level key prefix under which archive
	// objects land. Defaults to "telemetry".
	S3Prefix string
	// S3Region is the AWS region. Required when S3Bucket is set
	// (unless S3Endpoint is set, in which case region is best-
	// effort populated by the SDK).
	S3Region string
	// S3Endpoint overrides the AWS endpoint URL. Used for MinIO,
	// R2, GCS-via-S3, and other S3-compatible stores. Empty means
	// "use the canonical AWS endpoint for S3Region".
	S3Endpoint string
	// S3AccessKeyID / S3SecretAccessKey override the SDK's default
	// credentials chain (env / file / IMDS / SSO). When both are
	// blank the writer uses the default chain.
	S3AccessKeyID     string
	S3SecretAccessKey string
	// S3StorageClass selects the S3 storage class for archive
	// objects. Defaults to STANDARD_IA. Set to STANDARD if you
	// plan to read the archive frequently.
	S3StorageClass string
	// S3FlushInterval, MaxBytesPerObject, MaxEventsPerObject:
	// tune the cold-path buffering. Defaults: 30s, 16 MiB, 50k
	// events per object.
	S3FlushInterval      time.Duration
	S3MaxBytesPerObject  int
	S3MaxEventsPerObject int

	// ReplayDurable is the JetStream durable consumer name the
	// replay worker maintains on SNG_DLQ. Defaults to
	// "sng-telemetry-replay". Allowing operators to override this
	// makes blue/green replay possible (two workers on two durable
	// names tracking separate offsets).
	ReplayDurable string
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
			// PG_APP_ROLE uses getStrAllowEmpty (not getStr) because
			// an explicitly empty value is the documented escape
			// hatch for dev environments where a single PG_USER is
			// granted DML directly without role-separation. Treating
			// `PG_APP_ROLE=` and `PG_APP_ROLE` (unset) identically —
			// as plain getStr would — would silently bury that
			// escape hatch and force every dev to either provision
			// `sng_app` or live with confusing SET SESSION ROLE
			// errors. validate() enforces non-empty in production.
			AppRole:          getStrAllowEmpty("PG_APP_ROLE", "sng_app"),
			ReadReplicaHosts: splitCSV(getStr("PG_READ_REPLICA_HOSTS", "")),
			// ReadReplicaPort + PgBouncerMode are populated by the
			// strict tables below so a typo fails boot rather than
			// silently reverting to the default.
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
		Policy: Policy{
			SigningKeyPath:    getStr("POLICY_SIGNING_KEY_PATH", ""),
			KeyWrapMasterB64:  getStr("POLICY_KEY_WRAP_MASTER_B64", ""),
			KeyWrapMasterFile: getStr("POLICY_KEY_WRAP_MASTER_FILE", ""),
		},
		Telemetry: Telemetry{
			OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceVersion: getStr("SERVICE_VERSION", ""),
		},
		TelemetryAnalytics: TelemetryAnalytics{
			ClickHouseEndpoints: splitCSV(getStr("CLICKHOUSE_ENDPOINTS", "")),
			ClickHouseDatabase:  getStr("CLICKHOUSE_DATABASE", ""),
			ClickHouseTable:     getStr("CLICKHOUSE_TABLE", ""),
			ClickHouseUsername:  getStr("CLICKHOUSE_USERNAME", ""),
			ClickHousePassword:  getStr("CLICKHOUSE_PASSWORD", ""),
			S3Bucket:            getStr("S3_TELEMETRY_BUCKET", ""),
			S3Prefix:            getStr("S3_TELEMETRY_PREFIX", ""),
			S3Region:            getStr("S3_TELEMETRY_REGION", ""),
			S3Endpoint:          getStr("S3_TELEMETRY_ENDPOINT", ""),
			S3AccessKeyID:       getStr("S3_TELEMETRY_ACCESS_KEY_ID", ""),
			S3SecretAccessKey:   getStr("S3_TELEMETRY_SECRET_ACCESS_KEY", ""),
			S3StorageClass:      getStr("S3_TELEMETRY_STORAGE_CLASS", ""),
			ReplayDurable:       getStr("TELEMETRY_REPLAY_DURABLE", ""),
		},
		AI: AI{
			Endpoint: getStr("AI_LLM_ENDPOINT", ""),
			APIKey:   getStr("AI_LLM_API_KEY", ""),
			Model:    getStr("AI_LLM_MODEL", ""),
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
		// 0 = inherit primary PG_PORT (see Postgres.ReplicaPort).
		{"PG_READ_REPLICA_PORT", 0, &cfg.Postgres.ReadReplicaPort},
		{"NATS_MAX_RECONNECTS", -1, &cfg.NATS.MaxReconnects},
		{"NATS_REPLICAS", 1, &cfg.NATS.Replicas},
		{"NATS_PARTITIONS", 1, &cfg.NATS.Partitions},
		{"NATS_FETCH_BATCH_SIZE", 50, &cfg.NATS.FetchBatchSize},
		{"NATS_PUBLISH_RETRY_ATTEMPTS", 3, &cfg.NATS.PublishRetryAttempts},
		{"RATE_LIMIT_BURST", 60, &cfg.RateLimit.Burst},
		{"WEBHOOK_MAX_ATTEMPTS", 6, &cfg.Webhook.MaxAttempts},
		{"WEBHOOK_BATCH_SIZE", 32, &cfg.Webhook.BatchSize},
		// Round-4 of Devin Review on PR #41 (PR D): wire the
		// integration delivery worker's tuning knobs through the
		// strict int parser so a typo (e.g.
		// `INTEGRATION_WORKER_BATCH_SIZE="32a"`) fails boot
		// loudly instead of silently reverting to the hard-coded
		// default. Defaults match
		// internal/service/integration/worker.go:46-65.
		{"INTEGRATION_WORKER_MAX_ATTEMPTS", 8, &cfg.Integration.MaxAttempts},
		{"INTEGRATION_WORKER_BATCH_SIZE", 32, &cfg.Integration.BatchSize},
		// Kept in sync with apikey.DefaultMaxActiveKeys; literal
		// here so the config package doesn't take a dependency on
		// internal/service/apikey.
		{"AUTH_API_KEY_MAX_ACTIVE_PER_TENANT", 64, &cfg.Auth.APIKeyMaxActivePerTenant},
		// AI guardrail tuning knobs. Defaults match
		// internal/service/ai.GuardrailConfig.normalize() (60 rpm,
		// 100000 tokens/day) so operators can tune per-tenant cost
		// controls without recompiling. Parsed strictly because a
		// typo silently reverting to the default would weaken a rate
		// limit / cost control.
		{"AI_GUARDRAIL_MAX_REQUESTS_PER_MINUTE", 60, &cfg.AI.GuardrailMaxRequestsPerMinute},
		{"AI_GUARDRAIL_MAX_TOKENS_PER_DAY", 100000, &cfg.AI.GuardrailMaxTokensPerDay},
		{"CLICKHOUSE_BATCH_SIZE", 1024, &cfg.TelemetryAnalytics.ClickHouseBatchSize},
		{"CLICKHOUSE_MAX_BACKLOG_MULTIPLIER", 4, &cfg.TelemetryAnalytics.ClickHouseMaxBacklogMultiplier},
		{"S3_TELEMETRY_MAX_BYTES_PER_OBJECT", 16 * 1024 * 1024, &cfg.TelemetryAnalytics.S3MaxBytesPerObject},
		{"S3_TELEMETRY_MAX_EVENTS_PER_OBJECT", 50_000, &cfg.TelemetryAnalytics.S3MaxEventsPerObject},
		// Per-tenant cap on registered OIDC IdP configs. Parsed
		// strictly so a typo can't silently revert the limit.
		{"MOBILE_AUTH_MAX_PROVIDERS_PER_TENANT", 10, &cfg.MobileAuth.MaxProvidersPerTenant},
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
		{"WEBHOOK_POLL_INTERVAL", time.Second, &cfg.Webhook.PollInterval},
		{"WEBHOOK_PROCESSING_TIMEOUT", 5 * time.Minute, &cfg.Webhook.ProcessingTimeout},
		// Integration delivery worker duration knobs.
		{"INTEGRATION_WORKER_BACKOFF_BASE", 30 * time.Second, &cfg.Integration.BackoffBase},
		{"INTEGRATION_WORKER_BACKOFF_MAX", time.Hour, &cfg.Integration.BackoffMax},
		{"INTEGRATION_WORKER_POLL_INTERVAL", time.Second, &cfg.Integration.PollInterval},
		{"INTEGRATION_WORKER_PROCESSING_TIMEOUT", 5 * time.Minute, &cfg.Integration.ProcessingTimeout},
		{"AUTH_ACCESS_TOKEN_TTL", time.Hour, &cfg.Auth.AccessTokenTTL},
		{"AUTH_CLAIM_TOKEN_TTL", 24 * time.Hour, &cfg.Auth.ClaimTokenTTL},
		{"CLICKHOUSE_FLUSH_INTERVAL", 2 * time.Second, &cfg.TelemetryAnalytics.ClickHouseFlushInterval},
		{"S3_TELEMETRY_FLUSH_INTERVAL", 30 * time.Second, &cfg.TelemetryAnalytics.S3FlushInterval},
		{"APP_REGISTRY_SYNC_INTERVAL", 24 * time.Hour, &cfg.AppRegistry.SyncInterval},
		{"AI_LLM_TIMEOUT", 10 * time.Second, &cfg.AI.Timeout},
		// Mobile IdP-federation session + discovery-cache lifetimes.
		{"MOBILE_AUTH_SESSION_TOKEN_TTL", time.Hour, &cfg.MobileAuth.SessionTokenTTL},
		{"MOBILE_AUTH_DISCOVERY_CACHE_TTL", 24 * time.Hour, &cfg.MobileAuth.DiscoveryCacheTTL},
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
		{"PG_PGBOUNCER_MODE", false, &cfg.Postgres.PgBouncerMode},
		{"RATE_LIMIT_ENABLED", true, &cfg.RateLimit.Enabled},
		{"CLICKHOUSE_TLS", false, &cfg.TelemetryAnalytics.ClickHouseTLS},
		{"CLICKHOUSE_ENSURE_SCHEMA", true, &cfg.TelemetryAnalytics.ClickHouseEnsureSchema},
		{"CLICKHOUSE_SHARDING", false, &cfg.TelemetryAnalytics.ClickHouseSharding},
		{"APP_REGISTRY_SYNC_ENABLED", true, &cfg.AppRegistry.SyncEnabled},
		{"MOBILE_AUTH_AUTO_PROVISION_USERS", true, &cfg.MobileAuth.AutoProvisionUsers},
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

	// Detect retired environment variables and fail loudly so an
	// operator upgrading the binary cannot silently fall back to
	// the default while their old setting is ignored. The previous
	// `WEBHOOK_MAX_RETRIES=N` meant "N retries on top of the first
	// attempt" (i.e. N+1 total). The new `WEBHOOK_MAX_ATTEMPTS=N`
	// means "N total deliveries". Silently reading only the new
	// name would turn a previously-set `WEBHOOK_MAX_RETRIES=6`
	// (= 7 attempts) into the default `WEBHOOK_MAX_ATTEMPTS=6`
	// (= 6 attempts) — a behaviour change the operator never
	// consented to. Refusing to boot forces a conscious migration
	// (`WEBHOOK_MAX_ATTEMPTS=7` if they want the old behaviour).
	if v, ok := os.LookupEnv("WEBHOOK_MAX_RETRIES"); ok {
		return cfg, fmt.Errorf(
			"WEBHOOK_MAX_RETRIES is no longer supported (was found: %q); "+
				"rename to WEBHOOK_MAX_ATTEMPTS and add 1 to preserve the "+
				"previous behaviour (old: N retries on top of the first "+
				"attempt = N+1 total; new: N total deliveries)", v)
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
	// PG_READ_REPLICA_PORT: 0 means "inherit PG_PORT" (see
	// Postgres.ReplicaPort). Any explicit value must be a valid TCP
	// port so a typo fails boot rather than producing an
	// unconnectable replica DSN at first read.
	if c.Postgres.ReadReplicaPort != 0 &&
		(c.Postgres.ReadReplicaPort < 1 || c.Postgres.ReadReplicaPort > 65535) {
		return fmt.Errorf("PG_READ_REPLICA_PORT out of range [1,65535] (0 inherits PG_PORT): %d", c.Postgres.ReadReplicaPort)
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
	// NATS_PARTITIONS is the telemetry stream cell count. 1 keeps
	// the historical single-stream layout; >1 fans out into N cells
	// (SNG_TELEMETRY_0…). Reject 0/negative (which would leave the
	// partitioner with no cells to hash into) and cap the upper
	// bound so a typo like NATS_PARTITIONS=100000 can't try to
	// stand up an absurd number of streams/consumers at boot.
	if c.NATS.Partitions < 1 || c.NATS.Partitions > 256 {
		return fmt.Errorf("NATS_PARTITIONS out of range [1,256]: %d", c.NATS.Partitions)
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Rate <= 0 {
			return fmt.Errorf("RATE_LIMIT_RATE must be > 0 when enabled, got %v", c.RateLimit.Rate)
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("RATE_LIMIT_BURST must be > 0 when enabled, got %d", c.RateLimit.Burst)
		}
	}
	// WEBHOOK_MAX_ATTEMPTS is the total delivery-attempt budget
	// (first try + retries). The worker's defaults() function uses
	// `<= 0` as the "unset, fall through to package default"
	// sentinel, which means an operator who set MaxAttempts=0 to
	// express "single attempt, no retries" would silently get the
	// hard-coded default of 8 instead — their configuration ignored.
	// Require >= 1 (same pattern as NATS_PUBLISH_RETRY_ATTEMPTS) so
	// the validator and the worker agree on what "set" means.
	// Operators wanting a single attempt with no retries set this
	// to 1.
	if c.Webhook.MaxAttempts < 1 {
		return fmt.Errorf("WEBHOOK_MAX_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.Webhook.MaxAttempts)
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
	if c.Webhook.BatchSize <= 0 {
		return fmt.Errorf("WEBHOOK_BATCH_SIZE must be > 0, got %d", c.Webhook.BatchSize)
	}
	if c.Webhook.PollInterval <= 0 {
		return fmt.Errorf("WEBHOOK_POLL_INTERVAL must be > 0, got %s", c.Webhook.PollInterval)
	}
	// WEBHOOK_PROCESSING_TIMEOUT <= DeliveryTimeout would let the
	// stuck-row reaper steal a row from a worker that's still
	// inside its HTTP call — double-delivery hazard. Force the
	// reaper window to be strictly larger than the per-attempt
	// timeout so a genuinely in-flight delivery cannot be
	// reclaimed under any race.
	if c.Webhook.ProcessingTimeout <= c.Webhook.DeliveryTimeout {
		return fmt.Errorf("WEBHOOK_PROCESSING_TIMEOUT (%s) must be > WEBHOOK_DELIVERY_TIMEOUT (%s) to prevent stuck-row reaper from racing in-flight deliveries", c.Webhook.ProcessingTimeout, c.Webhook.DeliveryTimeout)
	}
	// Integration delivery worker — same invariants as the
	// webhook worker. Reject 0 explicitly so the strict parser's
	// 0s acceptance cannot let an operator's misconfigured value
	// fall through to the worker's hard-coded default.
	if c.Integration.MaxAttempts < 1 {
		return fmt.Errorf("INTEGRATION_WORKER_MAX_ATTEMPTS must be >= 1 (set to 1 for a single attempt with no retries), got %d", c.Integration.MaxAttempts)
	}
	if c.Integration.BackoffBase <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_BACKOFF_BASE must be > 0, got %s", c.Integration.BackoffBase)
	}
	if c.Integration.BackoffMax < c.Integration.BackoffBase {
		return fmt.Errorf("INTEGRATION_WORKER_BACKOFF_MAX (%s) must be >= INTEGRATION_WORKER_BACKOFF_BASE (%s)", c.Integration.BackoffMax, c.Integration.BackoffBase)
	}
	if c.Integration.BatchSize <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_BATCH_SIZE must be > 0, got %d", c.Integration.BatchSize)
	}
	if c.Integration.PollInterval <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_POLL_INTERVAL must be > 0, got %s", c.Integration.PollInterval)
	}
	if c.Integration.ProcessingTimeout <= 0 {
		return fmt.Errorf("INTEGRATION_WORKER_PROCESSING_TIMEOUT must be > 0, got %s", c.Integration.ProcessingTimeout)
	}
	// AUTH_ACCESS_TOKEN_TTL <= 0 makes every issued token already
	// expired, which would silently lock every operator out of the
	// console. Forbid here so the strict parser's lenient acceptance
	// of "0s" is caught at boot rather than at first sign-in.
	if c.Auth.AccessTokenTTL <= 0 {
		return fmt.Errorf("AUTH_ACCESS_TOKEN_TTL must be > 0, got %s", c.Auth.AccessTokenTTL)
	}
	if c.Auth.ClaimTokenTTL <= 0 {
		return fmt.Errorf("AUTH_CLAIM_TOKEN_TTL must be > 0, got %s", c.Auth.ClaimTokenTTL)
	}
	if c.Auth.JWTSecret == "" && c.Environment.IsProduction() {
		return errors.New("AUTH_JWT_SECRET must be set in production environments")
	}
	if c.Environment.IsProduction() && c.NATS.TLSInsecure {
		return errors.New("NATS_TLS_INSECURE must be false in production environments")
	}
	// PG_APP_ROLE must be set in production. The Postgres pool's
	// AfterConnect hook adopts this role via SET SESSION ROLE so
	// RLS policies — which Postgres bypasses for superusers — apply
	// to every query. Running production with an empty AppRole
	// means the pool connects as PG_USER directly; if PG_USER is a
	// superuser (the common case for cloud-managed PG), RLS would
	// silently bypass. Fail boot rather than running with the
	// security model neutered.
	if c.Environment.IsProduction() && c.Postgres.AppRole == "" {
		return errors.New("PG_APP_ROLE must be set to a non-empty role in production environments (the runtime adopts this role via SET SESSION ROLE to enforce RLS; see docs/deploy.md)")
	}
	// The active-key cap blocks unbounded creation; disabling it
	// in production is almost always a misconfiguration. Tests
	// can still pass 0 via WithMaxActiveKeys directly without
	// going through env-config.
	if c.Environment.IsProduction() && c.Auth.APIKeyMaxActivePerTenant <= 0 {
		return errors.New("AUTH_API_KEY_MAX_ACTIVE_PER_TENANT must be > 0 in production environments (the cap protects against unbounded key creation; see docs/deploy.md)")
	}
	// Same rationale as the API-key cap above: the IdP-config handler
	// treats <= 0 as "unlimited", so allowing it in production would
	// silently disable the per-tenant provider cap and permit
	// unbounded idp_configs creation.
	if c.Environment.IsProduction() && c.MobileAuth.MaxProvidersPerTenant <= 0 {
		return errors.New("MOBILE_AUTH_MAX_PROVIDERS_PER_TENANT must be > 0 in production environments (the cap protects against unbounded IdP-config creation; see docs/deploy.md)")
	}
	// Same rationale as AUTH_ACCESS_TOKEN_TTL above: a <= 0 value would
	// be silently overridden by the service's 1h default
	// (OIDCService.sessionTTL) instead of honouring operator intent, so
	// "0s" must fail loudly at boot rather than minting unexpectedly
	// scoped sessions.
	if c.MobileAuth.SessionTokenTTL <= 0 {
		return fmt.Errorf("MOBILE_AUTH_SESSION_TOKEN_TTL must be > 0, got %s", c.MobileAuth.SessionTokenTTL)
	}
	// Likewise, a <= 0 discovery-cache TTL would silently fall back to
	// the service's 24h default rather than the configured value.
	if c.MobileAuth.DiscoveryCacheTTL <= 0 {
		return fmt.Errorf("MOBILE_AUTH_DISCOVERY_CACHE_TTL must be > 0, got %s", c.MobileAuth.DiscoveryCacheTTL)
	}
	if c.Policy.KeyWrapMasterB64 != "" && c.Policy.KeyWrapMasterFile != "" {
		return errors.New("POLICY_KEY_WRAP_MASTER_B64 and POLICY_KEY_WRAP_MASTER_FILE are mutually exclusive")
	}
	// Telemetry analytics: production requires authenticated
	// ClickHouse (anonymous default-user access is dangerous when
	// the cluster is reachable from the network) and an explicit
	// AWS region for the cold archive bucket (otherwise the SDK
	// silently picks `us-east-1`, which can violate data-residency
	// requirements). Both rules are skipped when the corresponding
	// sink is disabled.
	if c.Environment.IsProduction() && len(c.TelemetryAnalytics.ClickHouseEndpoints) > 0 {
		if c.TelemetryAnalytics.ClickHouseUsername == "" || c.TelemetryAnalytics.ClickHousePassword == "" {
			return errors.New("CLICKHOUSE_USERNAME and CLICKHOUSE_PASSWORD must be set in production when CLICKHOUSE_ENDPOINTS is configured (anonymous default-user access is unsafe over the network)")
		}
	}
	if c.TelemetryAnalytics.S3Bucket != "" && c.TelemetryAnalytics.S3Region == "" && c.TelemetryAnalytics.S3Endpoint == "" {
		return errors.New("S3_TELEMETRY_REGION must be set when S3_TELEMETRY_BUCKET is configured (or set S3_TELEMETRY_ENDPOINT for non-AWS S3-compatible stores)")
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

// splitCSV splits a comma-separated env-style list, trimming
// whitespace and dropping empty entries. Empty input → empty
// slice (not nil-vs-empty distinguished — callers treat both as
// "no values"). Used by env helpers that resolve into list-typed
// config fields (e.g. ClickHouse endpoints).
func splitCSV(in string) []string {
	if in == "" {
		return nil
	}
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func getStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// getStrAllowEmpty is the peer of `getStr` that distinguishes an
// unset environment variable from an explicitly empty one. Unset →
// `def`; set to empty string → empty string. Use this only for
// settings where the empty-string case is a meaningful operator
// signal (e.g. `PG_APP_ROLE=` to disable the SET SESSION ROLE
// hook in dev environments). Every other settings should use
// `getStr`, which treats empty and unset identically and is the
// safer default for fields where empty is never a valid value.
func getStrAllowEmpty(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
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
