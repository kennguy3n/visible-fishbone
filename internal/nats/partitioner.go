package nats

import (
	"fmt"
	"hash/fnv"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// TenantPartitioner maps a tenant_id to one of N telemetry
// partitions ("cells"). It is the routing primitive behind the
// horizontal telemetry-scaling layout: at high tenant counts a
// single JetStream stream + consumer becomes the throughput
// bottleneck, so the workload is fanned out across N independent
// streams (SNG_TELEMETRY_0 … SNG_TELEMETRY_{N-1}), each consumed by
// its own goroutine. A tenant is pinned to exactly one partition so
// every event for that tenant lands on the same stream and is
// processed (and rate-limited, and deduplicated) in one place.
//
// Mapping is a deterministic FNV-1a hash of the tenant_id modulo
// the partition count. The hash is stable across processes and
// builds, so every publisher and every consumer agree on a tenant's
// partition without coordination. The partition count is fixed at
// boot (NATS_PARTITIONS); changing it re-shuffles the tenant→cell
// assignment, which is an operational migration, not a hot reconfig
// — mirroring the fixed shard_count used by the ClickHouse
// sharded writer.
//
// TenantPartitioner is immutable after construction and safe for
// concurrent use.
type TenantPartitioner struct {
	partitions int
}

// NewTenantPartitioner returns a partitioner over `partitions`
// cells. A value < 1 is clamped to 1 (the single-cell, no-fan-out
// layout) so callers can pass an unvalidated config value safely;
// config.validate already bounds NATS_PARTITIONS to [1, 256].
func NewTenantPartitioner(partitions int) *TenantPartitioner {
	if partitions < 1 {
		partitions = 1
	}
	return &TenantPartitioner{partitions: partitions}
}

// PartitionerFromConfig builds a TenantPartitioner from the NATS
// config's Partitions knob.
func PartitionerFromConfig(cfg *config.NATS) *TenantPartitioner {
	if cfg == nil {
		return NewTenantPartitioner(1)
	}
	return NewTenantPartitioner(cfg.Partitions)
}

// Count returns the number of partitions.
func (tp *TenantPartitioner) Count() int { return tp.partitions }

// Enabled reports whether fan-out is active (more than one cell).
// When false the historical single-stream layout is in effect and
// callers should use the unpartitioned subjects/stream names.
func (tp *TenantPartitioner) Enabled() bool { return tp.partitions > 1 }

// Partition returns the partition index in [0, Count()) that owns
// tenantID. With a single partition this is always 0.
func (tp *TenantPartitioner) Partition(tenantID string) int {
	if tp.partitions <= 1 {
		return 0
	}
	h := fnv.New32a()
	// hash.Hash.Write never returns an error.
	_, _ = h.Write([]byte(tenantID))
	return int(h.Sum32() % uint32(tp.partitions))
}

// SubjectForTelemetryPartition builds the canonical subject for a
// telemetry event under the partitioned layout, e.g.
// SubjectForTelemetryPartition(3, "abc", "flow") →
// "sng.3.abc.telemetry.flow". The partition slot sits immediately
// after the prefix so a per-cell consumer can filter on
// `sng.<partition>.*.telemetry.>`.
func SubjectForTelemetryPartition(partition int, tenantID, class string) string {
	return fmt.Sprintf("%s.%d.%s.telemetry.%s", SubjectPrefix, partition, tenantID, class)
}

// SubjectForTenant returns the telemetry subject for an envelope's
// tenant/class, choosing the partitioned or unpartitioned layout
// based on whether fan-out is enabled. This is the single routing
// entry point the publisher uses so publish-side and consume-side
// subject shapes can never drift.
func (tp *TenantPartitioner) SubjectForTenant(tenantID, class string) string {
	if !tp.Enabled() {
		return SubjectForTelemetry(tenantID, class)
	}
	return SubjectForTelemetryPartition(tp.Partition(tenantID), tenantID, class)
}

// TelemetryPartitionStreamSuffix returns the stream-name suffix for
// partition i, e.g. "TELEMETRY_3" (→ stream "SNG_TELEMETRY_3").
func TelemetryPartitionStreamSuffix(partition int) string {
	return fmt.Sprintf("%s_%d", StreamSuffixTelemetry, partition)
}

// TelemetryPartitionSubject returns the stream/consumer filter
// subject for partition i, e.g. "sng.3.*.telemetry.>".
func TelemetryPartitionSubject(partition int) string {
	return fmt.Sprintf("%s.%d.*.telemetry.>", SubjectPrefix, partition)
}
