package config

import (
	"strings"
	"testing"
)

func TestNATSPartitionsRange(t *testing.T) {
	for _, p := range []string{"0", "-1", "257", "100000"} {
		clearAll(t)
		withEnv(t, map[string]string{
			"ENVIRONMENT":     "local",
			"NATS_PARTITIONS": p,
		})
		_, err := Load()
		if err == nil {
			t.Errorf("NATS_PARTITIONS=%s: expected validation error", p)
			continue
		}
		if !strings.Contains(err.Error(), "NATS_PARTITIONS") {
			t.Errorf("NATS_PARTITIONS=%s: error should mention NATS_PARTITIONS: %v", p, err)
		}
	}
}

func TestNATSPartitionsValid(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":     "local",
		"NATS_PARTITIONS": "8",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NATS.Partitions != 8 {
		t.Errorf("NATS.Partitions = %d, want 8", cfg.NATS.Partitions)
	}
}

func TestNATSPartitionsDefault(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{"ENVIRONMENT": "local", "NATS_PARTITIONS": ""})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NATS.Partitions != 1 {
		t.Errorf("default NATS.Partitions = %d, want 1", cfg.NATS.Partitions)
	}
}

func TestReadReplicaPortRange(t *testing.T) {
	for _, p := range []string{"-1", "65536", "70000"} {
		clearAll(t)
		withEnv(t, map[string]string{
			"ENVIRONMENT":          "local",
			"PG_READ_REPLICA_PORT": p,
		})
		_, err := Load()
		if err == nil {
			t.Errorf("PG_READ_REPLICA_PORT=%s: expected validation error", p)
			continue
		}
		if !strings.Contains(err.Error(), "PG_READ_REPLICA_PORT") {
			t.Errorf("PG_READ_REPLICA_PORT=%s: error should mention the var: %v", p, err)
		}
	}
}

func TestReadReplicaHostsParsed(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":           "local",
		"PG_READ_REPLICA_HOSTS": "replica-a, replica-b ,replica-c",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Postgres.ReadReplicaHosts
	want := []string{"replica-a", "replica-b", "replica-c"}
	if len(got) != len(want) {
		t.Fatalf("ReadReplicaHosts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ReadReplicaHosts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestClickHouseShardingStrictBool(t *testing.T) {
	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":         "local",
		"CLICKHOUSE_SHARDING": "maybe",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected strict-parse error for CLICKHOUSE_SHARDING=maybe")
	}

	clearAll(t)
	withEnv(t, map[string]string{
		"ENVIRONMENT":         "local",
		"CLICKHOUSE_SHARDING": "true",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.TelemetryAnalytics.ClickHouseSharding {
		t.Error("ClickHouseSharding = false, want true")
	}
}

func TestReplicaPortInheritsPrimary(t *testing.T) {
	t.Parallel()
	// 0 (default) inherits the primary port.
	p := Postgres{Port: 5432, ReadReplicaPort: 0}
	if got := p.ReplicaPort(); got != 5432 {
		t.Errorf("ReplicaPort() = %d, want 5432 (inherited)", got)
	}
	// Explicit non-zero overrides.
	p.ReadReplicaPort = 6432
	if got := p.ReplicaPort(); got != 6432 {
		t.Errorf("ReplicaPort() = %d, want 6432", got)
	}
}

func TestReplicaDSNOverridesHostAndPort(t *testing.T) {
	t.Parallel()
	p := Postgres{
		Host:     "primary.internal",
		Port:     5432,
		User:     "sng",
		Password: "secret",
		Database: "sng",
		SSLMode:  "require",
	}
	dsn := p.ReplicaDSN("replica.internal")
	if !strings.Contains(dsn, "host=replica.internal") {
		t.Errorf("ReplicaDSN missing replica host: %q", dsn)
	}
	if strings.Contains(dsn, "host=primary.internal") {
		t.Errorf("ReplicaDSN still references primary host: %q", dsn)
	}
	// Inherits auth + sslmode from the primary.
	for _, want := range []string{"user=sng", "dbname=sng", "sslmode=require"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("ReplicaDSN missing %q: %q", want, dsn)
		}
	}
}
