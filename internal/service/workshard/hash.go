package workshard

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"

	"github.com/google/uuid"
)

// shardIndex maps a tenant to one of shardCount shards. It is the same
// construction the telemetry store sharder uses
// (internal/service/telemetry/clickhouse): FNV-1a over the tenant
// UUID's 16 bytes, modulo the shard count. The parallel is deliberate —
// a tenant's background compute and its telemetry storage hash the same
// way — but the function is re-implemented here rather than imported so
// the work distributor carries no dependency on the telemetry package.
//
// shardCount <= 1 collapses to a single shard (shard 0), which is the
// single-replica / no-sharding degenerate case.
func shardIndex(tenantID uuid.UUID, shardCount int) int {
	if shardCount <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write(tenantID[:])
	return int(h.Sum32() % uint32(shardCount))
}

// hrwScore is the rendezvous (highest-random-weight) score for pairing
// a shard with a worker: FNV-1a over the shard number and the worker
// UUID. The worker with the highest score for a shard owns it. Because
// the score depends only on (shard, worker), adding or removing a
// worker changes the winner for a shard only when that worker was, or
// becomes, the maximum — so a membership change reassigns the minimal
// set of shards (roughly 1/N of them) rather than reshuffling all.
func hrwScore(shard int, worker uuid.UUID) uint64 {
	h := fnv.New64a()
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(shard))
	_, _ = h.Write(b[:])
	_, _ = h.Write(worker[:])
	return h.Sum64()
}

// hrwWinner returns the worker that owns shard under rendezvous hashing.
// workers must be non-empty. Ties on score (astronomically unlikely for
// distinct 64-bit hashes, but possible) break toward the lexically
// smaller worker UUID so every replica computes an identical winner.
func hrwWinner(shard int, workers []uuid.UUID) uuid.UUID {
	best := workers[0]
	bestScore := hrwScore(shard, best)
	for _, w := range workers[1:] {
		sc := hrwScore(shard, w)
		if sc > bestScore || (sc == bestScore && bytes.Compare(w[:], best[:]) < 0) {
			best, bestScore = w, sc
		}
	}
	return best
}

// ownedShards returns, in ascending order, the shards for which me is
// the rendezvous winner among workers. An empty worker set yields no
// shards.
func ownedShards(shardCount int, workers []uuid.UUID, me uuid.UUID) []int {
	if len(workers) == 0 {
		return nil
	}
	var out []int
	for shard := 0; shard < shardCount; shard++ {
		if hrwWinner(shard, workers) == me {
			out = append(out, shard)
		}
	}
	return out
}
