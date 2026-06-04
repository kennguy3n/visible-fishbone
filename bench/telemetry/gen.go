package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// epochBase anchors generated event timestamps so a run is
// reproducible. Events are stamped at the generator's base time plus a
// per-event microsecond offset, keeping schema.Envelope.Validate (which
// rejects a zero timestamp) satisfied without depending on wall-clock
// time. It is the default base when GenConfig.BaseTime is unset.
var epochBase = time.Unix(1_700_000_000, 0).UTC()

// GenConfig parameterises the synthetic telemetry generator. The
// generator is deterministic for a fixed Seed so a run is byte-for-byte
// reproducible — every bench run that fixes the seed crafts the same
// envelope stream.
type GenConfig struct {
	// Tenants is the size of the tenant pool events are distributed
	// across. Used to exercise per-tenant fairness and sharding.
	Tenants int
	// DevicesPerTenant is the per-tenant device pool size. Duplicates
	// replay a verbatim envelope (same EventID), which is what the
	// consumer's EventID dedup ring keys on under schema version 1.
	DevicesPerTenant int
	// Seed seeds the PRNG. A fixed seed makes the stream reproducible.
	Seed uint64
	// DuplicateRate is the fraction [0,1) of events that re-emit a
	// recently-generated envelope verbatim (same EventID) to exercise
	// the dedup layer. 0 disables duplicates.
	DuplicateRate float64
	// BaseTime anchors event timestamps. Zero defaults to epochBase, a
	// fixed historical instant that keeps dry-run output reproducible.
	// Live runners that write to ClickHouse must set this to a recent
	// wall-clock time so the per-row retain_until (timestamp +
	// retention) lands in the FUTURE — otherwise the table's TTL treats
	// the rows as already-expired and a background merge drops them out
	// from under a freshly-inserted read.
	BaseTime time.Time
}

func (c *GenConfig) fillDefaults() {
	if c.Tenants <= 0 {
		c.Tenants = 100
	}
	if c.DevicesPerTenant <= 0 {
		c.DevicesPerTenant = 16
	}
	if c.DuplicateRate < 0 {
		c.DuplicateRate = 0
	}
	if c.BaseTime.IsZero() {
		c.BaseTime = epochBase
	}
}

// recentRingSize bounds the ring of recently-generated envelopes the
// generator draws duplicates from. Large enough that duplicates land
// outside the immediately-preceding event (a realistic replay pattern)
// but small enough to stay cache-resident.
const recentRingSize = 1024

// Generator crafts a reproducible stream of schema.Envelope values
// spread across a fixed tenant/device pool. It is NOT safe for
// concurrent use — each producer goroutine in the live benches owns its
// own Generator seeded distinctly so the aggregate stream stays
// deterministic per worker.
type Generator struct {
	cfg     GenConfig
	rng     *rand.Rand
	tenants []uuid.UUID
	// devices[t] is the device pool for tenant t.
	devices [][]uuid.UUID

	emitted uint64

	recent    []schema.Envelope
	recentLen int
	recentPos int
}

// NewGenerator builds a generator over a deterministic tenant/device
// pool. The pools are derived from the seed so two generators with the
// same config address the same tenants (important for the e2e bench,
// where the publisher and the query side must agree on tenant IDs).
func NewGenerator(cfg GenConfig) *Generator {
	cfg.fillDefaults()
	// Two distinct PCG streams from the one seed; the second word is a
	// fixed nothing-up-my-sleeve constant so the pool is stable. A
	// deterministic PRNG is the point here (reproducible synthetic
	// load), not a security primitive.
	rng := rand.New(rand.NewPCG(cfg.Seed, 0x9E3779B97F4A7C15)) //nolint:gosec // deterministic synthetic data, not security-sensitive
	g := &Generator{
		cfg:     cfg,
		rng:     rng,
		tenants: make([]uuid.UUID, cfg.Tenants),
		devices: make([][]uuid.UUID, cfg.Tenants),
		recent:  make([]schema.Envelope, recentRingSize),
	}
	for t := 0; t < cfg.Tenants; t++ {
		g.tenants[t] = g.randUUID()
		g.devices[t] = make([]uuid.UUID, cfg.DevicesPerTenant)
		for d := 0; d < cfg.DevicesPerTenant; d++ {
			g.devices[t][d] = g.randUUID()
		}
	}
	return g
}

// TenantID returns the i-th tenant in the pool (modulo pool size).
func (g *Generator) TenantID(i int) uuid.UUID {
	return g.tenants[((i%len(g.tenants))+len(g.tenants))%len(g.tenants)]
}

// BaseTime returns the instant event timestamps are anchored to.
func (g *Generator) BaseTime() time.Time { return g.cfg.BaseTime }

// TenantCount returns the size of the tenant pool.
func (g *Generator) TenantCount() int { return len(g.tenants) }

// Next returns the next envelope in the stream. With probability
// DuplicateRate it returns a verbatim copy of a recently-generated
// envelope (to drive the dedup layer); otherwise it crafts a fresh
// flow event for a uniformly-chosen tenant/device.
func (g *Generator) Next() schema.Envelope {
	if g.recentLen > 0 && g.rng.Float64() < g.cfg.DuplicateRate {
		idx := g.rng.IntN(g.recentLen)
		return g.recent[idx]
	}
	env := g.craft()
	g.recent[g.recentPos] = env
	g.recentPos = (g.recentPos + 1) % len(g.recent)
	if g.recentLen < len(g.recent) {
		g.recentLen++
	}
	return env
}

// platforms is the closed set the generator samples Platform from.
var platforms = []schema.Platform{
	schema.PlatformWindows, schema.PlatformMacOS, schema.PlatformLinux,
	schema.PlatformIOS, schema.PlatformAndroid,
}

// trafficClasses is the closed set of valid envelope traffic classes
// (mirrors schema.validTrafficClasses, which is unexported).
var trafficClasses = []string{
	"trusted_direct", "trusted_media_bypass", "inspect_lite",
	"inspect_full", "tunnel_private", "block",
}

func (g *Generator) craft() schema.Envelope {
	t := g.rng.IntN(len(g.tenants))
	d := g.rng.IntN(len(g.devices[t]))
	g.emitted++

	flow := schema.FlowEvent{
		SrcIP:      g.randIP().String(),
		DstIP:      g.randIP().String(),
		SrcPort:    uint16(1024 + g.rng.IntN(64000)),
		DstPort:    g.randDstPort(),
		Protocol:   g.pick([]string{"tcp", "udp"}),
		AppID:      g.pick([]string{"https", "dns", "quic", "ssh", "smtp", ""}),
		Verdict:    g.randVerdict(),
		Score:      float32(g.rng.Float64()),
		BytesIn:    uint64(g.rng.IntN(1 << 20)),
		BytesOut:   uint64(g.rng.IntN(1 << 20)),
		DurationMs: uint32(g.rng.IntN(60000)),
	}
	meta := schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       g.randUUID(),
		TenantID:      g.tenants[t],
		DeviceID:      g.devices[t][d],
		Timestamp:     g.cfg.BaseTime.Add(time.Duration(g.emitted) * time.Microsecond),
		Platform:      platforms[g.rng.IntN(len(platforms))],
	}
	env, err := schema.WrapFlowEvent(meta, trafficClasses[g.rng.IntN(len(trafficClasses))], flow)
	if err != nil {
		// WrapFlowEvent only fails if PackPayload fails, which cannot
		// happen for a well-formed FlowEvent crafted above; surface it
		// loudly rather than emitting a zero envelope into the stream.
		panic(fmt.Sprintf("bench: craft flow envelope: %v", err))
	}
	return env
}

func (g *Generator) randVerdict() schema.Verdict {
	vs := []schema.Verdict{
		schema.VerdictAllow, schema.VerdictDeny, schema.VerdictInspect,
		schema.VerdictAlert, schema.VerdictLog,
	}
	return vs[g.rng.IntN(len(vs))]
}

func (g *Generator) randDstPort() uint16 {
	common := []uint16{80, 443, 53, 22, 25, 3389, 8080}
	if g.rng.Float64() < 0.7 {
		return common[g.rng.IntN(len(common))]
	}
	return uint16(1 + g.rng.IntN(65534))
}

func (g *Generator) pick(opts []string) string { return opts[g.rng.IntN(len(opts))] }

func (g *Generator) randIP() netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], g.rng.Uint32())
	return netip.AddrFrom4(b)
}

// randUUID builds a RFC-4122 v4 UUID from the PRNG so generation stays
// deterministic (uuid.New() would pull from crypto/rand).
func (g *Generator) randUUID() uuid.UUID {
	var u uuid.UUID
	binary.BigEndian.PutUint64(u[0:8], g.rng.Uint64())
	binary.BigEndian.PutUint64(u[8:16], g.rng.Uint64())
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return u
}
