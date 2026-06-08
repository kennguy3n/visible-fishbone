package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// withEnv temporarily sets the given environment variables for the
// duration of the test and restores the prior state afterwards.
// Unset values can be provided as the empty string.
func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		prev, had := os.LookupEnv(k)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
		if v == "" {
			_ = os.Unsetenv(k)
		} else {
			_ = os.Setenv(k, v)
		}
	}
}

// clearAll removes every env var the config package reads. Useful
// when a test needs to ensure no ambient host environment leaks in.
func clearAll(t *testing.T) {
	t.Helper()
	keys := []string{
		"ENVIRONMENT", "APP_NAME",
		"LOG_LEVEL", "LOG_FORMAT",
		"HTTP_HOST", "HTTP_PORT", "HTTP_READ_TIMEOUT", "HTTP_READ_HEADER_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_SHUTDOWN_TIMEOUT",
		"NATS_URL", "NATS_NAME", "NATS_USER", "NATS_PASSWORD", "NATS_TOKEN", "NATS_CREDS_FILE",
		"NATS_TLS_CA", "NATS_TLS_CERT", "NATS_TLS_KEY", "NATS_TLS_INSECURE",
		"NATS_RECONNECT_WAIT", "NATS_MAX_RECONNECTS", "NATS_CONNECT_TIMEOUT", "NATS_REQUEST_TIMEOUT",
		"NATS_PUBLISH_RETRY_ATTEMPTS", "NATS_PUBLISH_RETRY_DELAY",
		"NATS_DEDUP_WINDOW", "NATS_REPLICAS", "NATS_STORAGE",
		"NATS_FETCH_BATCH_SIZE", "NATS_FETCH_MAX_WAIT", "NATS_STREAM_PREFIX",
		"PG_HOST", "PG_PORT", "PG_USER", "PG_PASSWORD", "PG_DATABASE", "PG_SSLMODE",
		"PG_MAX_OPEN_CONNS", "PG_MIN_CONNS", "PG_CONN_MAX_LIFETIME", "PG_CONN_TIMEOUT", "PG_APP_ROLE",
		"RATE_LIMIT_ENABLED", "RATE_LIMIT_RATE", "RATE_LIMIT_BURST",
		"RATE_LIMIT_CLEANUP_INTERVAL", "RATE_LIMIT_IDLE_TTL", "RATE_LIMIT_TRUSTED_PROXIES",
		"CORS_ALLOWED_ORIGINS", "CORS_ALLOWED_METHODS", "CORS_ALLOWED_HEADERS", "CORS_MAX_AGE",
		"WEBHOOK_MAX_ATTEMPTS", "WEBHOOK_MAX_RETRIES", "WEBHOOK_INITIAL_DELAY", "WEBHOOK_MAX_DELAY",
		"WEBHOOK_DELIVERY_TIMEOUT", "WEBHOOK_SIGNATURE_HEADER",
		"WEBHOOK_BATCH_SIZE", "WEBHOOK_POLL_INTERVAL", "WEBHOOK_PROCESSING_TIMEOUT",
		"INTEGRATION_WORKER_MAX_ATTEMPTS", "INTEGRATION_WORKER_BATCH_SIZE",
		"INTEGRATION_WORKER_BACKOFF_BASE", "INTEGRATION_WORKER_BACKOFF_MAX",
		"INTEGRATION_WORKER_POLL_INTERVAL", "INTEGRATION_WORKER_PROCESSING_TIMEOUT",
		"AUTH_JWT_SECRET", "AUTH_JWT_ISSUER", "AUTH_JWT_AUDIENCE", "AUTH_ACCESS_TOKEN_TTL", "AUTH_CLAIM_TOKEN_TTL", "AUTH_API_KEY_HEADER",
		"IAM_CORE_ISSUER", "IAM_CORE_JWKS_URL", "IAM_CORE_OIDC_DISCOVERY", "IAM_CORE_CLIENT_ID", "IAM_CORE_CLIENT_SECRET",
		"IAM_CORE_AUDIENCE", "IAM_CORE_MGMT_BASE_URL", "IAM_CORE_MGMT_AUDIENCE", "IAM_CORE_REDIRECT_URL",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "SERVICE_VERSION",
		"METRICS_ENABLED", "METRICS_PORT", "METRICS_NAMESPACE",
		"POP_REGISTRY_REFRESH_INTERVAL", "POP_HEALTH_TTL", "POP_HIGH_WATER_FRACTION",
		"POP_GEODNS_HOSTNAME", "POP_GEODNS_ROUTING_POLICY", "POP_GEODNS_TTL",
		"POP_GEODNS_PUBLISH_INTERVAL", "POP_REBALANCE_ENABLED", "POP_REBALANCE_INTERVAL",
		"AI_LLM_ENDPOINT", "AI_LLM_API_KEY", "AI_LLM_MODEL", "AI_LLM_MODEL_FAMILY", "AI_LLM_TIMEOUT",
		"AI_GUARDRAIL_MAX_REQUESTS_PER_MINUTE", "AI_GUARDRAIL_MAX_TOKENS_PER_DAY",
	}
	for _, k := range keys {
		k := k
		prev, had := os.LookupEnv(k)
		t.Cleanup(func() {
			// Critical: cleanup must put the environment back
			// to its exact pre-test state. If the key was set
			// before, restore it; if it wasn't, unset it (a
			// `.env` file or a sibling test may have injected
			// the key in between, and leaking it across tests
			// produced order-dependent failures).
			if had {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
		_ = os.Unsetenv(k)
	}
}

func TestLoadDefaults(t *testing.T) {
	clearAll(t)
	// Load() reads .env from the working directory. Run from a tmp
	// dir so we don't accidentally pick up a developer's .env.
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppName != "sng-control" {
		t.Errorf("AppName = %q, want sng-control", cfg.AppName)
	}
	if cfg.Environment != EnvironmentLocal {
		t.Errorf("Environment = %q, want local", cfg.Environment)
	}
	if !cfg.Environment.IsDevelopment() {
		t.Error("expected local environment to be IsDevelopment")
	}
	if cfg.Environment.IsProduction() {
		t.Error("local must not be IsProduction")
	}
	if cfg.HTTP.Port != 8080 {
		t.Errorf("HTTP.Port = %d, want 8080", cfg.HTTP.Port)
	}
	if cfg.HTTP.Addr() != "0.0.0.0:8080" {
		t.Errorf("HTTP.Addr = %q", cfg.HTTP.Addr())
	}
	if cfg.NATS.URL != "nats://127.0.0.1:4222" {
		t.Errorf("NATS.URL = %q", cfg.NATS.URL)
	}
	if cfg.NATS.StreamPrefix != "SNG" {
		t.Errorf("NATS.StreamPrefix = %q", cfg.NATS.StreamPrefix)
	}
	// ConnectTimeout and RequestTimeout are independent fields, so
	// both should default to 5s. If a future change makes them
	// share state we want the test to fail loudly.
	if cfg.NATS.ConnectTimeout != 5*time.Second {
		t.Errorf("NATS.ConnectTimeout = %v, want 5s", cfg.NATS.ConnectTimeout)
	}
	if cfg.NATS.RequestTimeout != 5*time.Second {
		t.Errorf("NATS.RequestTimeout = %v, want 5s", cfg.NATS.RequestTimeout)
	}
	if cfg.Postgres.SSLMode != "disable" {
		t.Errorf("Postgres.SSLMode = %q", cfg.Postgres.SSLMode)
	}
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled default should be true")
	}
	if cfg.Webhook.SignatureHeader != "X-SNG-Signature" {
		t.Errorf("Webhook.SignatureHeader = %q", cfg.Webhook.SignatureHeader)
	}
	// Worker-tunable defaults must match the values documented on
	// Webhook (and consumed by the worker via the buildRouter
	// translation in cmd/sng-control/main.go). A regression here
	// means the strict-table default and the docstring drifted.
	if cfg.Webhook.BatchSize != 32 {
		t.Errorf("Webhook.BatchSize = %d, want 32", cfg.Webhook.BatchSize)
	}
	if cfg.Webhook.PollInterval != time.Second {
		t.Errorf("Webhook.PollInterval = %s, want 1s", cfg.Webhook.PollInterval)
	}
	if cfg.Webhook.ProcessingTimeout != 5*time.Minute {
		t.Errorf("Webhook.ProcessingTimeout = %s, want 5m", cfg.Webhook.ProcessingTimeout)
	}
	// Integration delivery worker — defaults must match the
	// hard-coded values in internal/service/integration/worker.go
	// so an operator who exports no INTEGRATION_WORKER_* env vars
	// sees the same behaviour the worker would on a
	// `WorkerConfig{}`. Round-4 of Devin Review on PR #41 (PR D)
	// flagged the previous wiring where the strict-table parsed
	// values silently bypassed the worker; this pins that the
	// table + the worker defaults stay in sync.
	if cfg.Integration.MaxAttempts != 8 {
		t.Errorf("Integration.MaxAttempts = %d, want 8", cfg.Integration.MaxAttempts)
	}
	if cfg.Integration.BatchSize != 32 {
		t.Errorf("Integration.BatchSize = %d, want 32", cfg.Integration.BatchSize)
	}
	if cfg.Integration.PollInterval != time.Second {
		t.Errorf("Integration.PollInterval = %s, want 1s", cfg.Integration.PollInterval)
	}
	if cfg.Integration.BackoffBase != 30*time.Second {
		t.Errorf("Integration.BackoffBase = %s, want 30s", cfg.Integration.BackoffBase)
	}
	if cfg.Integration.BackoffMax != time.Hour {
		t.Errorf("Integration.BackoffMax = %s, want 1h", cfg.Integration.BackoffMax)
	}
	if cfg.Integration.ProcessingTimeout != 5*time.Minute {
		t.Errorf("Integration.ProcessingTimeout = %s, want 5m", cfg.Integration.ProcessingTimeout)
	}
	// Metrics defaults: enabled, port 9090, namespace "sng".
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled default should be true")
	}
	if cfg.Metrics.Port != 9090 {
		t.Errorf("Metrics.Port = %d, want 9090", cfg.Metrics.Port)
	}
	if cfg.Metrics.Namespace != "sng" {
		t.Errorf("Metrics.Namespace = %q, want sng", cfg.Metrics.Namespace)
	}
}

// TestLoadMetricsValidation exercises the strict parsing and
// validation of the METRICS_* knobs added for the observability
// stack.
func TestLoadMetricsValidation(t *testing.T) {
	loadIn := func(t *testing.T) (Config, error) {
		t.Helper()
		tmp := t.TempDir()
		wd, _ := os.Getwd()
		if err := os.Chdir(tmp); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(wd) })
		return Load()
	}

	t.Run("overrides", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_PORT", "9123")
		t.Setenv("METRICS_NAMESPACE", "acme")
		cfg, err := loadIn(t)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Metrics.Port != 9123 {
			t.Errorf("Metrics.Port = %d, want 9123", cfg.Metrics.Port)
		}
		if cfg.Metrics.Namespace != "acme" {
			t.Errorf("Metrics.Namespace = %q, want acme", cfg.Metrics.Namespace)
		}
	})

	t.Run("disabled skips port validation", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_ENABLED", "false")
		// Collide with HTTP port — must be tolerated when disabled.
		t.Setenv("METRICS_PORT", "8080")
		cfg, err := loadIn(t)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Metrics.Enabled {
			t.Error("Metrics.Enabled should be false")
		}
	})

	t.Run("port collision rejected when enabled", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_PORT", "8080") // == default HTTP_PORT
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for METRICS_PORT == HTTP_PORT")
		}
	})

	t.Run("out of range port rejected", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_PORT", "70000")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for out-of-range METRICS_PORT")
		}
	})

	t.Run("non-integer port rejected", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_PORT", "not-a-number")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for non-integer METRICS_PORT")
		}
	})

	t.Run("invalid namespace rejected", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_NAMESPACE", "1bad-ns")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for invalid METRICS_NAMESPACE")
		}
	})

	t.Run("non-boolean enabled rejected", func(t *testing.T) {
		clearAll(t)
		t.Setenv("METRICS_ENABLED", "yes")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for non-boolean METRICS_ENABLED")
		}
	})
}

// TestIntegrationWorkerEnvOverridesReachConfig verifies the
// round-4 fix on PR #41 (PR D): `INTEGRATION_WORKER_*` env vars
// flow through `Load` to the `cfg.Integration.*` fields that
// `cmd/sng-control/main.go` threads into the live worker. The
// previous wiring used `integration.WorkerConfig{}`, so the
// strict parser would accept these env vars at boot but the
// worker never saw them.
func TestIntegrationWorkerEnvOverridesReachConfig(t *testing.T) {
	clearAll(t)
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	t.Setenv("INTEGRATION_WORKER_MAX_ATTEMPTS", "11")
	t.Setenv("INTEGRATION_WORKER_BATCH_SIZE", "7")
	t.Setenv("INTEGRATION_WORKER_BACKOFF_BASE", "15s")
	t.Setenv("INTEGRATION_WORKER_BACKOFF_MAX", "30m")
	t.Setenv("INTEGRATION_WORKER_POLL_INTERVAL", "250ms")
	t.Setenv("INTEGRATION_WORKER_PROCESSING_TIMEOUT", "2m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Integration.MaxAttempts != 11 {
		t.Errorf("Integration.MaxAttempts = %d, want 11", cfg.Integration.MaxAttempts)
	}
	if cfg.Integration.BatchSize != 7 {
		t.Errorf("Integration.BatchSize = %d, want 7", cfg.Integration.BatchSize)
	}
	if cfg.Integration.BackoffBase != 15*time.Second {
		t.Errorf("Integration.BackoffBase = %s, want 15s", cfg.Integration.BackoffBase)
	}
	if cfg.Integration.BackoffMax != 30*time.Minute {
		t.Errorf("Integration.BackoffMax = %s, want 30m", cfg.Integration.BackoffMax)
	}
	if cfg.Integration.PollInterval != 250*time.Millisecond {
		t.Errorf("Integration.PollInterval = %s, want 250ms", cfg.Integration.PollInterval)
	}
	if cfg.Integration.ProcessingTimeout != 2*time.Minute {
		t.Errorf("Integration.ProcessingTimeout = %s, want 2m", cfg.Integration.ProcessingTimeout)
	}
}

// TestIntegrationWorkerValidationRejectsBadValues confirms each
// guard added in `validate()` for the integration worker rejects
// the bad value with an actionable error message naming the env
// var.
func TestIntegrationWorkerValidationRejectsBadValues(t *testing.T) {
	cases := []struct {
		name   string
		env    string
		value  string
		expect string
	}{
		{"MaxAttempts<1", "INTEGRATION_WORKER_MAX_ATTEMPTS", "0", "INTEGRATION_WORKER_MAX_ATTEMPTS"},
		{"BackoffBase<=0", "INTEGRATION_WORKER_BACKOFF_BASE", "0s", "INTEGRATION_WORKER_BACKOFF_BASE"},
		{"BackoffMax<Base", "INTEGRATION_WORKER_BACKOFF_MAX", "5s", "INTEGRATION_WORKER_BACKOFF_MAX"},
		{"BatchSize<=0", "INTEGRATION_WORKER_BATCH_SIZE", "0", "INTEGRATION_WORKER_BATCH_SIZE"},
		{"PollInterval<=0", "INTEGRATION_WORKER_POLL_INTERVAL", "0s", "INTEGRATION_WORKER_POLL_INTERVAL"},
		{"ProcessingTimeout<=0", "INTEGRATION_WORKER_PROCESSING_TIMEOUT", "0s", "INTEGRATION_WORKER_PROCESSING_TIMEOUT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAll(t)
			tmp := t.TempDir()
			wd, _ := os.Getwd()
			if err := os.Chdir(tmp); err != nil {
				t.Fatalf("chdir: %v", err)
			}
			t.Cleanup(func() { _ = os.Chdir(wd) })

			// BackoffMax<Base test needs Base set; supply the
			// default 30s explicitly so the case is unambiguous.
			if tc.env == "INTEGRATION_WORKER_BACKOFF_MAX" {
				t.Setenv("INTEGRATION_WORKER_BACKOFF_BASE", "30s")
			}
			t.Setenv(tc.env, tc.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load: want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.expect)
			}
		})
	}
}

func TestEnvironmentValid(t *testing.T) {
	for _, env := range []Environment{EnvironmentLocal, EnvironmentDev, EnvironmentQA, EnvironmentUAT, EnvironmentProd} {
		if !env.Valid() {
			t.Errorf("%s should be valid", env)
		}
	}
	if Environment("bogus").Valid() {
		t.Error("bogus environment should not be valid")
	}
}

// TestProductionRejectsJWTSecret pins the inverted production
// contract introduced with the build-tagged HMAC removal (Gap #11):
// the symmetric HMAC dev-signing path is compiled out of production
// builds, so a configured AUTH_JWT_SECRET in uat/prod is a
// security-relevant misconfiguration and must fail boot. The absence
// of the secret in production is the supported configuration.
func TestProductionRejectsJWTSecret(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":       "prod",
		"AUTH_JWT_SECRET":   "supersecret",
		"NATS_TLS_INSECURE": "false",
		"PG_SSLMODE":        "require",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for AUTH_JWT_SECRET set in prod")
	}
	if !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Errorf("error should mention AUTH_JWT_SECRET: %v", err)
	}
}

// TestProductionAllowsAbsentJWTSecret verifies the supported
// production posture: with AUTH_JWT_SECRET unset, validation passes
// (identity is terminated at the gateway via OIDC).
func TestProductionAllowsAbsentJWTSecret(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":       "prod",
		"NATS_TLS_INSECURE": "false",
		"PG_SSLMODE":        "require",
	})
	if _, err := Load(); err != nil {
		t.Fatalf("prod config with no AUTH_JWT_SECRET should be valid: %v", err)
	}
}

func TestProductionRequiresPGSSL(t *testing.T) {
	// Production requires a sslmode that GUARANTEES TLS. `disable`
	// is plaintext; `allow` and `prefer` accept silent downgrades
	// to plaintext if the server doesn't insist on TLS. Only
	// `require`, `verify-ca`, and `verify-full` are acceptable in
	// prod. This test covers all three rejected modes and the
	// three accepted modes so a future relaxation of the rule
	// can't slip through unnoticed.
	rejected := []string{"disable", "allow", "prefer"}
	accepted := []string{"require", "verify-ca", "verify-full"}

	for _, mode := range rejected {
		t.Run("rejected_"+mode, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{
				"ENVIRONMENT": "prod",
				"PG_SSLMODE":  mode,
			})
			_, err := Load()
			if err == nil {
				t.Fatalf("expected validation error for %q sslmode in prod", mode)
			}
			if !strings.Contains(err.Error(), "PG_SSLMODE") {
				t.Errorf("error should mention PG_SSLMODE: %v", err)
			}
		})
	}
	for _, mode := range accepted {
		t.Run("accepted_"+mode, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{
				"ENVIRONMENT": "prod",
				"PG_SSLMODE":  mode,
			})
			if _, err := Load(); err != nil {
				t.Fatalf("did not expect error for %q sslmode in prod: %v", mode, err)
			}
		})
	}
}

func TestStrictIntParseError(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"HTTP_PORT": "80a",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected strict-parse error for HTTP_PORT")
	}
	if !strings.Contains(err.Error(), "HTTP_PORT") {
		t.Errorf("error should mention HTTP_PORT: %v", err)
	}
}

func TestStrictDurationParseError(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"HTTP_READ_TIMEOUT": "5second",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected strict-parse error for HTTP_READ_TIMEOUT")
	}
}

func TestInvalidEnvironment(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT": "staging",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for unknown environment")
	}
}

func TestInvalidPGSSLMode(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT": "local",
		"PG_SSLMODE":  "yolo",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for invalid PG_SSLMODE")
	}
}

func TestInvalidNATSStorage(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":  "local",
		"NATS_STORAGE": "tape",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for invalid NATS_STORAGE")
	}
}

func TestInvalidAILLMModelFamily(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":         "local",
		"AI_LLM_MODEL_FAMILY": "ternary-bonasi", // typo
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for invalid AI_LLM_MODEL_FAMILY")
	}
	if !strings.Contains(err.Error(), "AI_LLM_MODEL_FAMILY") {
		t.Errorf("error should mention AI_LLM_MODEL_FAMILY: %v", err)
	}
}

func TestValidAILLMModelFamilyValues(t *testing.T) {
	for _, family := range []string{"", "auto", "ternary-bonsai", "openai-compat"} {
		family := family
		t.Run(family, func(t *testing.T) {
			clearAll(t)
			env := map[string]string{"ENVIRONMENT": "local"}
			if family != "" {
				env["AI_LLM_MODEL_FAMILY"] = family
			}
			withEnv(t, env)
			if _, err := Load(); err != nil {
				t.Fatalf("did not expect error for model family %q: %v", family, err)
			}
		})
	}
}

func TestPortRange(t *testing.T) {
	cases := []string{"0", "65536", "70000", "-1"}
	for _, p := range cases {
		clearAll(t)
		withEnv(t, map[string]string{
			"HTTP_PORT": p,
		})
		_, err := Load()
		if err == nil {
			t.Errorf("HTTP_PORT=%s: expected error", p)
		}
	}
}

func TestRateLimitDisabledSkipsValidation(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"RATE_LIMIT_ENABLED": "false",
		"RATE_LIMIT_RATE":    "0",
		"RATE_LIMIT_BURST":   "0",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected disabled rate limit to skip validation: %v", err)
	}
	if cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled should be false")
	}
}

func TestWebhookDelayInvariant(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"WEBHOOK_INITIAL_DELAY": "30s",
		"WEBHOOK_MAX_DELAY":     "1s",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error when max delay < initial delay")
	}
}

func TestPostgresDSN(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"PG_HOST":     "db.internal",
		"PG_PORT":     "5433",
		"PG_USER":     "sng_user",
		"PG_PASSWORD": "pw",
		"PG_DATABASE": "sng_test",
		"PG_SSLMODE":  "require",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dsn := cfg.Postgres.DSN()
	for _, want := range []string{"host=db.internal", "port=5433", "user=sng_user", "dbname=sng_test", "sslmode=require"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("DSN missing %q: %s", want, dsn)
		}
	}
}

func TestDotEnvLoading(t *testing.T) {
	clearAll(t)
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	envFile := filepath.Join(tmp, ".env")
	// METRICS_PORT is moved off its 9090 default here because this
	// test pins HTTP_PORT=9090; the strict validator rejects a
	// metrics port co-located with the public API port.
	contents := `# Test env
APP_NAME=from-dotenv
LOG_LEVEL="debug"
HTTP_PORT=9090
METRICS_PORT=9091
`
	if err := os.WriteFile(envFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppName != "from-dotenv" {
		t.Errorf("AppName from .env = %q", cfg.AppName)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level from .env = %q", cfg.Log.Level)
	}
	if cfg.HTTP.Port != 9090 {
		t.Errorf("HTTP.Port from .env = %d", cfg.HTTP.Port)
	}
}

func TestDotEnvDoesNotOverrideExistingEnv(t *testing.T) {
	clearAll(t)
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := os.WriteFile(".env", []byte("APP_NAME=from-dotenv\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	withEnv(t, map[string]string{"APP_NAME": "from-process"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppName != "from-process" {
		t.Errorf("AppName = %q, want from-process (process env should win)", cfg.AppName)
	}
}

func TestParseCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,c", []string{"a", "b", "c"}},
		{",a,,b,", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := parseCSV(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseCSV(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseCSV(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestMustLoadPanicsOnError(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"HTTP_PORT": "not-a-number",
	})
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustLoad should panic on invalid config")
		}
	}()
	_ = MustLoad()
}

func TestEnvironmentHelpers(t *testing.T) {
	for _, c := range []struct {
		env    Environment
		isDev  bool
		isProd bool
		strOut string
	}{
		{EnvironmentLocal, true, false, "local"},
		{EnvironmentDev, true, false, "dev"},
		{EnvironmentQA, false, false, "qa"},
		{EnvironmentUAT, false, true, "uat"},
		{EnvironmentProd, false, true, "prod"},
	} {
		if c.env.IsDevelopment() != c.isDev {
			t.Errorf("%s.IsDevelopment = %v, want %v", c.env, c.env.IsDevelopment(), c.isDev)
		}
		if c.env.IsProduction() != c.isProd {
			t.Errorf("%s.IsProduction = %v, want %v", c.env, c.env.IsProduction(), c.isProd)
		}
		if c.env.String() != c.strOut {
			t.Errorf("%s.String = %q", c.env, c.env.String())
		}
	}
}

func TestNATSTLSInsecureBlockedInProd(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":       "prod",
		"PG_SSLMODE":        "require",
		"NATS_TLS_INSECURE": "true",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for NATS_TLS_INSECURE=true in prod")
	}
}

func TestStrictIntJoinedErrors(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"HTTP_PORT": "abc",
		"PG_PORT":   "xyz",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected joined strict errors")
	}
	// errors.Join returns an error implementing Unwrap() []error.
	type multi interface{ Unwrap() []error }
	if m, ok := err.(multi); ok {
		if len(m.Unwrap()) < 2 {
			t.Errorf("expected at least 2 joined errors, got %d", len(m.Unwrap()))
		}
	} else {
		// Fallback: at least one of the offending vars should appear.
		s := err.Error()
		if !strings.Contains(s, "HTTP_PORT") && !strings.Contains(s, "PG_PORT") {
			t.Errorf("expected error to mention HTTP_PORT or PG_PORT, got %s", s)
		}
	}
}

func TestNATSRetryRangeValidation(t *testing.T) {
	// Negative is rejected (obvious nonsense).
	t.Run("negative_rejected", func(t *testing.T) {
		clearAll(t)
		withEnv(t, map[string]string{
			"NATS_PUBLISH_RETRY_ATTEMPTS": "-3",
		})
		_, err := Load()
		if err == nil {
			t.Fatal("expected validation error for negative NATS_PUBLISH_RETRY_ATTEMPTS")
		}
	})

	// Zero is also rejected — see config.go for why: the publisher's
	// fallback chain treats <= 0 as unset, so an operator who sets 0
	// expecting "fire-and-forget / single attempt" would silently get
	// the hard-coded fallback of 3 attempts. Force them to set 1.
	t.Run("zero_rejected", func(t *testing.T) {
		clearAll(t)
		withEnv(t, map[string]string{
			"NATS_PUBLISH_RETRY_ATTEMPTS": "0",
		})
		_, err := Load()
		if err == nil {
			t.Fatal("expected validation error for NATS_PUBLISH_RETRY_ATTEMPTS=0")
		}
		if !strings.Contains(err.Error(), "NATS_PUBLISH_RETRY_ATTEMPTS") {
			t.Errorf("expected error to mention NATS_PUBLISH_RETRY_ATTEMPTS, got %s", err.Error())
		}
	})

	// 1 is the documented "single attempt, no retries" value and
	// must be accepted.
	t.Run("one_accepted", func(t *testing.T) {
		clearAll(t)
		withEnv(t, map[string]string{
			"NATS_PUBLISH_RETRY_ATTEMPTS": "1",
		})
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected NATS_PUBLISH_RETRY_ATTEMPTS=1 to be accepted, got %v", err)
		}
		if cfg.NATS.PublishRetryAttempts != 1 {
			t.Errorf("expected PublishRetryAttempts=1, got %d", cfg.NATS.PublishRetryAttempts)
		}
	})
}

func TestCORSDefaults(t *testing.T) {
	clearAll(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.CORS.AllowedMethods) == 0 {
		t.Error("CORS.AllowedMethods should have defaults")
	}
	if len(cfg.CORS.AllowedHeaders) == 0 {
		t.Error("CORS.AllowedHeaders should have defaults")
	}
	if cfg.CORS.MaxAge != time.Hour {
		t.Errorf("CORS.MaxAge = %s, want 1h", cfg.CORS.MaxAge)
	}
}

func TestHTTPAddr(t *testing.T) {
	h := HTTP{Host: "10.0.0.1", Port: 9000}
	if got := h.Addr(); got != "10.0.0.1:9000" {
		t.Errorf("HTTP.Addr = %q, want 10.0.0.1:9000", got)
	}
}

func TestReadHeaderTimeoutLEReadTimeout(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"HTTP_READ_TIMEOUT":        "5s",
		"HTTP_READ_HEADER_TIMEOUT": "30s",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error when header timeout > read timeout")
	}
	if !strings.Contains(err.Error(), "HTTP_READ_HEADER_TIMEOUT") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPostgresPoolBounds(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"PG_MAX_OPEN_CONNS": "0",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for PG_MAX_OPEN_CONNS=0")
	}

	clearAll(t)
	withEnv(t, map[string]string{
		"PG_MAX_OPEN_CONNS": "5",
		"PG_MIN_CONNS":      "10",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected error when PG_MIN_CONNS > PG_MAX_OPEN_CONNS")
	}

	clearAll(t)
	withEnv(t, map[string]string{
		"PG_MAX_OPEN_CONNS": "9999999",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for very large PG_MAX_OPEN_CONNS")
	}
}

func TestLibpqQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "''"},
		{"sng", "sng"},
		{"disable", "disable"},
		{"my secret", "'my secret'"},
		{"with'quote", `'with\'quote'`},
		{`with\back`, `'with\\back'`},
		{"both'and\\", `'both\'and\\'`},
		{"trailing\t", "'trailing\t'"},
		{"with\nnewline", "'with\nnewline'"},
	}
	for _, c := range cases {
		if got := libpqQuote(c.in); got != c.want {
			t.Errorf("libpqQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPostgresDSNHandlesSpecialChars(t *testing.T) {
	p := Postgres{
		Host:        "db.internal",
		Port:        5432,
		User:        "sng",
		Password:    "p@ss w'rd\\x",
		Database:    "sng db",
		SSLMode:     "require",
		ConnTimeout: 5 * time.Second,
	}
	dsn := p.DSN()
	// pgxpool.ParseConfig accepts both URI and libpq KV formats.
	// Round-tripping through the upstream parser is the only
	// reliable check that escaping is correct.
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig rejected DSN %q: %v", dsn, err)
	}
	if cfg.ConnConfig.Password != p.Password {
		t.Errorf("password round-trip mismatch: got %q, want %q",
			cfg.ConnConfig.Password, p.Password)
	}
	if cfg.ConnConfig.Database != p.Database {
		t.Errorf("database round-trip mismatch: got %q, want %q",
			cfg.ConnConfig.Database, p.Database)
	}
}

func TestStrictNumericRejectsTypo(t *testing.T) {
	// One representative for each of the int, duration and float
	// strict paths so a regression that drops a field from the
	// strict tables produces a clear failure.
	for _, c := range []struct {
		key, bad string
	}{
		{"HTTP_PORT", "80a"},
		{"NATS_REPLICAS", "two"},
		{"RATE_LIMIT_BURST", "ten"},
		{"WEBHOOK_MAX_ATTEMPTS", "six"},
		{"PG_MIN_CONNS", "five"},
		{"HTTP_SHUTDOWN_TIMEOUT", "10seconds"},
		{"NATS_REQUEST_TIMEOUT", "5sec"},
		{"NATS_CONNECT_TIMEOUT", "five_seconds"},
		{"NATS_DEDUP_WINDOW", "forever"},
		{"AUTH_ACCESS_TOKEN_TTL", "lifetime"},
		{"RATE_LIMIT_RATE", "thirty"},
	} {
		c := c
		t.Run(c.key, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{c.key: c.bad})
			if _, err := Load(); err == nil {
				t.Fatalf("expected boot-time error for %s=%q", c.key, c.bad)
			} else if !strings.Contains(err.Error(), c.key) {
				t.Fatalf("error %q should mention %s", err.Error(), c.key)
			}
		})
	}
}

// TestLoad_RejectsRetiredWebhookMaxRetries — when an operator
// upgrades the binary while leaving `WEBHOOK_MAX_RETRIES=N` in
// their environment, Load() must refuse to boot with a clear
// message rather than silently falling back to the
// `WEBHOOK_MAX_ATTEMPTS` default (which has different semantics —
// "N retries on top of the first" vs "N total deliveries").
// Forcing the operator to ack the rename prevents a stealth
// behavioural change at upgrade time.
func TestLoad_RejectsRetiredWebhookMaxRetries(t *testing.T) {
	clearAll(t)
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	t.Setenv("WEBHOOK_MAX_RETRIES", "6")
	_, err := Load()
	if err == nil {
		t.Fatal("Load() succeeded with retired WEBHOOK_MAX_RETRIES set; want error")
	}
	if !strings.Contains(err.Error(), "WEBHOOK_MAX_RETRIES") ||
		!strings.Contains(err.Error(), "WEBHOOK_MAX_ATTEMPTS") {
		t.Errorf("error %q does not name both the retired and replacement variables", err)
	}
}

func TestLoadDotEnvInlineCommentsAndExport(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	contents := strings.Join([]string{
		"# header comment",
		"",
		"export FOO=bar",
		"BAZ=qux # trailing comment",
		"PASS='p#1' # outside",
		`QUOTED="value # not a comment"`,
		"NOSPACE=secret#1",
		"\texport TABBED=tabbed",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	clearAll(t)
	t.Cleanup(func() {
		for _, k := range []string{"FOO", "BAZ", "PASS", "QUOTED", "NOSPACE", "TABBED"} {
			_ = os.Unsetenv(k)
		}
	})
	if err := loadDotEnv(envPath); err != nil {
		t.Fatalf("loadDotEnv: %v", err)
	}
	expect := map[string]string{
		"FOO":     "bar",
		"BAZ":     "qux",
		"PASS":    "p#1",
		"QUOTED":  "value # not a comment",
		"NOSPACE": "secret#1",
		"TABBED":  "tabbed",
	}
	for k, want := range expect {
		got, ok := os.LookupEnv(k)
		if !ok {
			t.Errorf("%s not set", k)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// TestStrictBoolRejectsTypos guards the security-/correctness-adjacent
// boolean fields. Both NATS_TLS_INSECURE and RATE_LIMIT_ENABLED can
// flip the operator's intent in either direction on a silent
// fall-back to the default; strict parsing must reject any value
// strconv.ParseBool refuses.
func TestStrictBoolRejectsTypos(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string // substring of error message
	}{
		{
			name: "NATS_TLS_INSECURE typo",
			env:  map[string]string{"NATS_TLS_INSECURE": "yes"},
			want: "NATS_TLS_INSECURE",
		},
		{
			name: "RATE_LIMIT_ENABLED typo",
			env:  map[string]string{"RATE_LIMIT_ENABLED": "no"},
			want: "RATE_LIMIT_ENABLED",
		},
		{
			name: "NATS_TLS_INSECURE garbage",
			env:  map[string]string{"NATS_TLS_INSECURE": "trueeee"},
			want: "NATS_TLS_INSECURE",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearAll(t)
			withEnv(t, c.env)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected strict-bool error for %v", c.env)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should mention %s: %v", c.want, err)
			}
		})
	}
}

// TestStrictBoolAcceptsCanonicalValues confirms strconv.ParseBool's
// documented value set still flows through Load() into the
// destination fields. Belt-and-braces: a future refactor that
// switched to a custom parser could quietly tighten the accepted set.
func TestStrictBoolAcceptsCanonicalValues(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true}, {"t", true}, {"T", true}, {"TRUE", true}, {"true", true}, {"True", true},
		{"0", false}, {"f", false}, {"F", false}, {"FALSE", false}, {"false", false}, {"False", false},
	}
	for _, c := range cases {
		t.Run("RATE_LIMIT_ENABLED="+c.val, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{"RATE_LIMIT_ENABLED": c.val})
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.RateLimit.Enabled != c.want {
				t.Errorf("RateLimit.Enabled = %v, want %v", cfg.RateLimit.Enabled, c.want)
			}
		})
	}
}

// TestDSNConnectTimeoutCeil documents the libpq fallback contract:
// connect_timeout is rendered as integer seconds and libpq treats
// 0 as "wait forever". Any positive sub-second duration MUST round
// up to at least 1s; non-positive values render as 0 but are
// rejected by validate() so cannot escape Load() in practice.
func TestDSNConnectTimeoutCeil(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string // substring of DSN
	}{
		{500 * time.Millisecond, "connect_timeout=1"},
		{time.Second, "connect_timeout=1"},
		{1500 * time.Millisecond, "connect_timeout=2"},
		{5 * time.Second, "connect_timeout=5"},
		{5500 * time.Millisecond, "connect_timeout=6"},
		// Non-positive values render 0 (libpq=infinite). validate()
		// blocks this at boot; the rendering itself is still
		// well-defined so a Postgres{} literal in unit tests is
		// deterministic.
		{0, "connect_timeout=0"},
		{-1 * time.Second, "connect_timeout=0"},
	}
	for _, c := range cases {
		t.Run(c.in.String(), func(t *testing.T) {
			p := Postgres{
				Host:        "h",
				Port:        5432,
				User:        "u",
				Password:    "p",
				Database:    "d",
				SSLMode:     "disable",
				ConnTimeout: c.in,
			}
			dsn := p.DSN()
			if !strings.Contains(dsn, c.want) {
				t.Errorf("DSN %q missing %q (in=%v)", dsn, c.want, c.in)
			}
		})
	}
}

// TestValidateRejectsZeroPGConnTimeout protects against a manually
// constructed Config (or a future Load() refactor) that lets a
// non-positive ConnTimeout reach the pgxpool / libpq fallback,
// where 0 is silently treated as "wait forever".
func TestValidateRejectsZeroPGConnTimeout(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{"PG_CONN_TIMEOUT": "0s"})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for PG_CONN_TIMEOUT=0")
	}
	if !strings.Contains(err.Error(), "PG_CONN_TIMEOUT") {
		t.Errorf("error should mention PG_CONN_TIMEOUT: %v", err)
	}
}

// TestValidateRejectsZeroTimeouts checks that the cluster of
// timeout-style durations rejects `0s` at boot. Each of these maps to
// a third-party client API (nats.Timeout, http.Client.Timeout, JWT TTL)
// where 0 is silently treated as "no deadline" / "already expired",
// which is operationally hostile. The strict env parser accepts "0s"
// without error, so validate() is the only line of defence.
func TestValidateRejectsZeroTimeouts(t *testing.T) {
	cases := []struct {
		name   string
		envKey string
		want   string
	}{
		{"NATS_CONNECT_TIMEOUT", "NATS_CONNECT_TIMEOUT", "NATS_CONNECT_TIMEOUT"},
		{"NATS_REQUEST_TIMEOUT", "NATS_REQUEST_TIMEOUT", "NATS_REQUEST_TIMEOUT"},
		{"WEBHOOK_DELIVERY_TIMEOUT", "WEBHOOK_DELIVERY_TIMEOUT", "WEBHOOK_DELIVERY_TIMEOUT"},
		{"AUTH_ACCESS_TOKEN_TTL", "AUTH_ACCESS_TOKEN_TTL", "AUTH_ACCESS_TOKEN_TTL"},
		{"MOBILE_AUTH_SESSION_TOKEN_TTL", "MOBILE_AUTH_SESSION_TOKEN_TTL", "MOBILE_AUTH_SESSION_TOKEN_TTL"},
		{"MOBILE_AUTH_DISCOVERY_CACHE_TTL", "MOBILE_AUTH_DISCOVERY_CACHE_TTL", "MOBILE_AUTH_DISCOVERY_CACHE_TTL"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clearAll(t)
			withEnv(t, map[string]string{tc.envKey: "0s"})
			_, err := Load()
			if err == nil {
				t.Fatalf("expected validation error for %s=0s", tc.envKey)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %s: %v", tc.want, err)
			}
		})
	}
}

// TestValidateRejectsWebhookProcessingTimeoutShorterThanDelivery
// locks in the cross-field invariant: the worker's stuck-row
// reaper window must be strictly larger than the per-attempt HTTP
// timeout. If the inequality is violated the reaper can steal a
// row from a worker that's still inside its outbound HTTP call,
// producing a duplicate webhook delivery downstream. We reject at
// boot so the operator is forced to fix the misconfiguration
// rather than discover it as a subscriber-side dedup bug under
// load.
func TestValidateRejectsWebhookProcessingTimeoutShorterThanDelivery(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"WEBHOOK_DELIVERY_TIMEOUT":   "30s",
		"WEBHOOK_PROCESSING_TIMEOUT": "15s",
	})
	_, err := Load()
	if err == nil {
		t.Fatalf("expected validation error when WEBHOOK_PROCESSING_TIMEOUT < WEBHOOK_DELIVERY_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "WEBHOOK_PROCESSING_TIMEOUT") || !strings.Contains(err.Error(), "WEBHOOK_DELIVERY_TIMEOUT") {
		t.Errorf("error should reference both knobs: %v", err)
	}
}

// TestValidateAcceptsZeroNATSDedupWindow documents the intentional
// asymmetry with the other NATS durations: NATS_DEDUP_WINDOW=0 disables
// JetStream's per-stream deduplication entirely, which is a legitimate
// operator opt-out when the downstream consumer is idempotent. We
// keep this test to lock in that we do NOT regress into rejecting 0.
func TestValidateAcceptsZeroNATSDedupWindow(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{"NATS_DEDUP_WINDOW": "0s"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with NATS_DEDUP_WINDOW=0s should succeed, got %v", err)
	}
	if cfg.NATS.DedupWindow != 0 {
		t.Errorf("NATS.DedupWindow = %v, want 0", cfg.NATS.DedupWindow)
	}
}

// setRawEnv sets `key` to `value` exactly — including the empty
// string — and restores the prior state at test cleanup. Unlike
// `withEnv` (which collapses `""` to unset), this helper preserves
// the unset-vs-set-empty distinction the config package now cares
// about for PG_APP_ROLE.
func setRawEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
	_ = os.Setenv(key, value)
}

// TestPGAppRoleEmptyEnvVarDisablesHook pins the documented escape
// hatch: `PG_APP_ROLE=` (explicitly empty) must yield
// `Postgres.AppRole == ""`, distinct from unset which yields the
// `sng_app` default. This is the load-bearing behaviour distinction
// between `getStr` and `getStrAllowEmpty` — if a future refactor
// rewires PG_APP_ROLE to use plain `getStr`, this test breaks.
func TestPGAppRoleEmptyEnvVarDisablesHook(t *testing.T) {
	clearAll(t)
	setRawEnv(t, "PG_APP_ROLE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with empty PG_APP_ROLE in dev should succeed, got %v", err)
	}
	if cfg.Postgres.AppRole != "" {
		t.Errorf("Postgres.AppRole = %q, want empty (the documented dev escape hatch)", cfg.Postgres.AppRole)
	}
}

// TestPGAppRoleUnsetUsesDefault pins the unset → "sng_app"
// default. Combined with TestPGAppRoleEmptyEnvVarDisablesHook,
// these two tests lock in that `getStrAllowEmpty` distinguishes
// the two cases.
func TestPGAppRoleUnsetUsesDefault(t *testing.T) {
	clearAll(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with unset PG_APP_ROLE should succeed, got %v", err)
	}
	if cfg.Postgres.AppRole != "sng_app" {
		t.Errorf("Postgres.AppRole = %q, want \"sng_app\" (the default)", cfg.Postgres.AppRole)
	}
}

// TestValidateRejectsEmptyAppRoleInProduction pins the production
// guard: an operator who sets PG_APP_ROLE=  in a production
// environment must fail boot rather than silently bypass the
// SET SESSION ROLE hook and run with whatever PG_USER grants
// (which is typically a superuser on cloud-managed PG, neutering
// the entire RLS security model).
func TestValidateRejectsEmptyAppRoleInProduction(t *testing.T) {
	clearAll(t)
	setRawEnv(t, "PG_APP_ROLE", "")
	withEnv(t, map[string]string{
		"ENVIRONMENT":       "prod",
		"PG_SSLMODE":        "require",
		"NATS_TLS_INSECURE": "false",
	})
	if _, err := Load(); err == nil {
		t.Fatal("Load() with empty PG_APP_ROLE in production should fail validation")
	} else if !strings.Contains(err.Error(), "PG_APP_ROLE") {
		t.Errorf("validation error should mention PG_APP_ROLE, got: %v", err)
	}
}

// TestTelemetryAnalytics_DefaultsAndOverrides pins the analytics
// config struct: every env var lands on the right field, defaults
// fire when unset, and CLICKHOUSE_ENDPOINTS splits on commas.
func TestTelemetryAnalytics_DefaultsAndOverrides(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"CLICKHOUSE_ENDPOINTS":               "ch-a:9000, ch-b:9000",
		"CLICKHOUSE_DATABASE":                "events",
		"CLICKHOUSE_TABLE":                   "telemetry",
		"CLICKHOUSE_USERNAME":                "writer",
		"CLICKHOUSE_PASSWORD":                "shh",
		"CLICKHOUSE_TLS":                     "true",
		"CLICKHOUSE_BATCH_SIZE":              "2048",
		"CLICKHOUSE_FLUSH_INTERVAL":          "5s",
		"CLICKHOUSE_ENSURE_SCHEMA":           "false",
		"S3_TELEMETRY_BUCKET":                "tel-cold",
		"S3_TELEMETRY_PREFIX":                "v1",
		"S3_TELEMETRY_REGION":                "us-west-2",
		"S3_TELEMETRY_ENDPOINT":              "https://minio.local:9000",
		"S3_TELEMETRY_ACCESS_KEY_ID":         "AKIA...",
		"S3_TELEMETRY_SECRET_ACCESS_KEY":     "...",
		"S3_TELEMETRY_STORAGE_CLASS":         "GLACIER_IR",
		"S3_TELEMETRY_FLUSH_INTERVAL":        "60s",
		"S3_TELEMETRY_MAX_BYTES_PER_OBJECT":  "33554432",
		"S3_TELEMETRY_MAX_EVENTS_PER_OBJECT": "100000",
		"TELEMETRY_REPLAY_DURABLE":           "sng-telemetry-replay-bg",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ta := cfg.TelemetryAnalytics
	if got, want := ta.ClickHouseEndpoints, []string{"ch-a:9000", "ch-b:9000"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("endpoints: %v", got)
	}
	if ta.ClickHouseDatabase != "events" || ta.ClickHouseTable != "telemetry" {
		t.Errorf("db/table: %s/%s", ta.ClickHouseDatabase, ta.ClickHouseTable)
	}
	if !ta.ClickHouseTLS {
		t.Errorf("tls should be true")
	}
	if ta.ClickHouseEnsureSchema {
		t.Errorf("ensure-schema should be false (explicitly disabled)")
	}
	if ta.ClickHouseBatchSize != 2048 {
		t.Errorf("batch size: %d", ta.ClickHouseBatchSize)
	}
	if ta.ClickHouseFlushInterval != 5*time.Second {
		t.Errorf("flush interval: %s", ta.ClickHouseFlushInterval)
	}
	if ta.S3Bucket != "tel-cold" || ta.S3Prefix != "v1" || ta.S3Region != "us-west-2" {
		t.Errorf("s3 bucket/prefix/region: %+v", ta)
	}
	if ta.S3Endpoint != "https://minio.local:9000" {
		t.Errorf("s3 endpoint: %s", ta.S3Endpoint)
	}
	if ta.S3StorageClass != "GLACIER_IR" {
		t.Errorf("storage class: %s", ta.S3StorageClass)
	}
	if ta.S3FlushInterval != 60*time.Second {
		t.Errorf("s3 flush interval: %s", ta.S3FlushInterval)
	}
	if ta.S3MaxBytesPerObject != 33554432 {
		t.Errorf("s3 max bytes: %d", ta.S3MaxBytesPerObject)
	}
	if ta.S3MaxEventsPerObject != 100000 {
		t.Errorf("s3 max events: %d", ta.S3MaxEventsPerObject)
	}
	if ta.ReplayDurable != "sng-telemetry-replay-bg" {
		t.Errorf("replay durable: %s", ta.ReplayDurable)
	}
}

// TestTelemetryAnalytics_S3BucketWithoutRegionFails confirms the
// validator rejects S3 wiring without a region (and without an
// endpoint override).
func TestTelemetryAnalytics_S3BucketWithoutRegionFails(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"S3_TELEMETRY_BUCKET": "tel-cold",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected validation error for missing region")
	}
}

// TestTelemetryAnalytics_ProdRequiresClickHouseAuth confirms
// production refuses anonymous ClickHouse access.
func TestTelemetryAnalytics_ProdRequiresClickHouseAuth(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":          "prod",
		"PG_SSLMODE":           "require",
		"CLICKHOUSE_ENDPOINTS": "clickhouse:9000",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for missing ClickHouse credentials in prod")
	}
	if !strings.Contains(err.Error(), "CLICKHOUSE_USERNAME") {
		t.Errorf("error should mention CLICKHOUSE_USERNAME: %v", err)
	}
}

// TestLoadIAMCore covers the Session 2A iam-core integration config:
// it is off by default, derives nothing when disabled, loads the
// IAM_CORE_* contract when enabled, and enforces the cross-field
// invariants (issuer URL shape, required audience, paired client
// credentials).
func TestLoadIAMCore(t *testing.T) {
	loadIn := func(t *testing.T) (Config, error) {
		t.Helper()
		tmp := t.TempDir()
		wd, _ := os.Getwd()
		if err := os.Chdir(tmp); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(wd) })
		return Load()
	}

	t.Run("disabled by default", func(t *testing.T) {
		clearAll(t)
		cfg, err := loadIn(t)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.IAMCore.Enabled() {
			t.Fatal("iam-core should be disabled when IAM_CORE_ISSUER is unset")
		}
	})

	t.Run("loads full contract", func(t *testing.T) {
		clearAll(t)
		t.Setenv("IAM_CORE_ISSUER", "https://iam.example.com/")
		t.Setenv("IAM_CORE_CLIENT_ID", "sng-gateway")
		t.Setenv("IAM_CORE_CLIENT_SECRET", "shh")
		t.Setenv("IAM_CORE_AUDIENCE", "sng-api")
		t.Setenv("IAM_CORE_REDIRECT_URL", "https://admin.sng.example.com/auth/callback")
		cfg, err := loadIn(t)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.IAMCore.Enabled() {
			t.Fatal("iam-core should be enabled")
		}
		// Trailing slash is trimmed so the issuer compares exactly to
		// the JWT `iss`.
		if cfg.IAMCore.Issuer != "https://iam.example.com" {
			t.Fatalf("issuer = %q", cfg.IAMCore.Issuer)
		}
		if cfg.IAMCore.ClientID != "sng-gateway" || cfg.IAMCore.ClientSecret != "shh" {
			t.Fatalf("client creds = %q/%q", cfg.IAMCore.ClientID, cfg.IAMCore.ClientSecret)
		}
		if cfg.IAMCore.Audience != "sng-api" {
			t.Fatalf("audience = %q", cfg.IAMCore.Audience)
		}
	})

	t.Run("issuer must be absolute URL", func(t *testing.T) {
		clearAll(t)
		t.Setenv("IAM_CORE_ISSUER", "iam.example.com")
		t.Setenv("IAM_CORE_AUDIENCE", "sng-api")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for non-URL issuer")
		}
	})

	t.Run("audience required when enabled", func(t *testing.T) {
		clearAll(t)
		t.Setenv("IAM_CORE_ISSUER", "https://iam.example.com")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error for missing audience")
		}
	})

	t.Run("client id and secret must be paired", func(t *testing.T) {
		clearAll(t)
		t.Setenv("IAM_CORE_ISSUER", "https://iam.example.com")
		t.Setenv("IAM_CORE_AUDIENCE", "sng-api")
		t.Setenv("IAM_CORE_CLIENT_ID", "sng-gateway")
		if _, err := loadIn(t); err == nil {
			t.Fatal("expected error when client secret missing")
		}
	})
}

// TestIAMCoreValidateIssuerScheme covers the environment-sensitive
// issuer-scheme rule: http:// is allowed in dev/qa (loopback test
// servers) but rejected in production (uat/prod), while https:// is
// always allowed. Exercised against IAMCore.validate directly so the
// production case need not satisfy every other prod-only config knob.
func TestIAMCoreValidateIssuerScheme(t *testing.T) {
	base := IAMCore{Audience: "sng-api"}
	cases := []struct {
		name    string
		issuer  string
		env     Environment
		wantErr bool
	}{
		{"http allowed in dev", "http://127.0.0.1:9000", EnvironmentDev, false},
		{"http allowed in qa", "http://iam.qa.internal", EnvironmentQA, false},
		{"http rejected in uat", "http://iam.example.com", EnvironmentUAT, true},
		{"http rejected in prod", "http://iam.example.com", EnvironmentProd, true},
		{"https allowed in prod", "https://iam.example.com", EnvironmentProd, false},
		{"bare host rejected everywhere", "iam.example.com", EnvironmentDev, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Issuer = tc.issuer
			err := c.validate(tc.env)
			if tc.wantErr && err == nil {
				t.Fatalf("validate(%q, %s): expected error, got nil", tc.issuer, tc.env)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate(%q, %s): unexpected error: %v", tc.issuer, tc.env, err)
			}
		})
	}
}
