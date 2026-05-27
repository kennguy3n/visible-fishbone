package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		"NATS_RECONNECT_WAIT", "NATS_MAX_RECONNECTS", "NATS_REQUEST_TIMEOUT",
		"NATS_PUBLISH_RETRY_ATTEMPTS", "NATS_PUBLISH_RETRY_DELAY",
		"NATS_DEDUP_WINDOW", "NATS_REPLICAS", "NATS_STORAGE",
		"NATS_FETCH_BATCH_SIZE", "NATS_FETCH_MAX_WAIT", "NATS_STREAM_PREFIX",
		"PG_HOST", "PG_PORT", "PG_USER", "PG_PASSWORD", "PG_DATABASE", "PG_SSLMODE",
		"PG_MAX_OPEN_CONNS", "PG_MAX_IDLE_CONNS", "PG_CONN_MAX_LIFETIME", "PG_CONN_TIMEOUT", "PG_APP_ROLE",
		"RATE_LIMIT_ENABLED", "RATE_LIMIT_RATE", "RATE_LIMIT_BURST",
		"RATE_LIMIT_CLEANUP_INTERVAL", "RATE_LIMIT_IDLE_TTL", "RATE_LIMIT_TRUSTED_PROXIES",
		"CORS_ALLOWED_ORIGINS", "CORS_ALLOWED_METHODS", "CORS_ALLOWED_HEADERS", "CORS_MAX_AGE",
		"WEBHOOK_MAX_RETRIES", "WEBHOOK_INITIAL_DELAY", "WEBHOOK_MAX_DELAY",
		"WEBHOOK_DELIVERY_TIMEOUT", "WEBHOOK_SIGNATURE_HEADER",
		"AUTH_JWT_SECRET", "AUTH_JWT_ISSUER", "AUTH_JWT_AUDIENCE", "AUTH_ACCESS_TOKEN_TTL", "AUTH_API_KEY_HEADER",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "SERVICE_VERSION",
	}
	for _, k := range keys {
		prev, had := os.LookupEnv(k)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, prev)
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
	if cfg.Postgres.SSLMode != "disable" {
		t.Errorf("Postgres.SSLMode = %q", cfg.Postgres.SSLMode)
	}
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled default should be true")
	}
	if cfg.Webhook.SignatureHeader != "X-SNG-Signature" {
		t.Errorf("Webhook.SignatureHeader = %q", cfg.Webhook.SignatureHeader)
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

func TestProductionRequiresJWTSecret(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":       "prod",
		"AUTH_JWT_SECRET":   "",
		"NATS_TLS_INSECURE": "false",
		"PG_SSLMODE":        "require",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for missing JWT secret in prod")
	}
	if !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Errorf("error should mention AUTH_JWT_SECRET: %v", err)
	}
}

func TestProductionRequiresPGSSL(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":     "prod",
		"AUTH_JWT_SECRET": "supersecret",
		"PG_SSLMODE":      "disable",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for disable sslmode in prod")
	}
	if !strings.Contains(err.Error(), "PG_SSLMODE") {
		t.Errorf("error should mention PG_SSLMODE: %v", err)
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
	contents := `# Test env
APP_NAME=from-dotenv
LOG_LEVEL="debug"
HTTP_PORT=9090
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
		"AUTH_JWT_SECRET":   "supersecret",
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
	clearAll(t)
	withEnv(t, map[string]string{
		"NATS_PUBLISH_RETRY_ATTEMPTS": "-3",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected validation error for negative NATS_PUBLISH_RETRY_ATTEMPTS")
	}
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
		"PG_MAX_IDLE_CONNS": "10",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected error when PG_MAX_IDLE_CONNS > PG_MAX_OPEN_CONNS")
	}

	clearAll(t)
	withEnv(t, map[string]string{
		"PG_MAX_OPEN_CONNS": "9999999",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for very large PG_MAX_OPEN_CONNS")
	}
}
