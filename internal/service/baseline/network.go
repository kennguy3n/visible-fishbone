// Package baseline — network.go layers four network-level anomaly
// detectors on top of the Welford/EWMA Detector:
//
//	port scan        — one source touching many distinct dst ports
//	lateral movement — one internal source fanning out to many
//	                   internal destinations
//	data exfiltration— large outbound volume to a single (often
//	                   newly-seen) destination
//	beaconing        — periodic, low-jitter connections to one
//	                   external host
//
// Design: the detectors do NOT invent their own statistics. Each
// reduces a window of flows to a single scalar feature per signal,
// then routes that feature through the SAME baseline estimator the
// rest of the package uses (Detector.observeFoldScore). That buys
// three things for free, exactly as WS3 requires:
//
//  1. The Welford/EWMA model learns each tenant's normal level for
//     the feature (a busy CDN edge legitimately fans out to many
//     ports; a quiet branch office does not).
//  2. The per-tenant feedback loop (alert.Feedback) tunes the
//     ZThreshold per (dimension, window) — i.e. per signal — so a
//     noisy signal self-desensitises and a quiet one sharpens.
//  3. Alerts flow into the existing alert.Router via AlertEmitter.
//
// Unlike the generic z-score alert, the network detectors attach
// the offending entity (source IP, destination, port count, period)
// to the alert evidence so an operator can act without re-deriving
// it from raw flows. The feature is computed at the tenant level
// (the max over all entities in the window) so the dimension set
// stays bounded — four dimensions per tenant, not one-per-IP.
package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Network anomaly dimensions. Stable strings so the per-tenant
// baseline rows + feedback-tuned thresholds persist across process
// restarts. Kept under a `net.` prefix to namespace them away from
// the application-level baseline dimensions (auth.*, dns.*, …).
const (
	DimPortScan   = "net.portscan.distinct_ports"
	DimLateral    = "net.lateral.internal_fanout"
	DimExfil      = "net.exfil.dst_bytes_out"
	DimBeaconing  = "net.beacon.regularity"
	KindPortScan  = "net.port_scan"
	KindLateral   = "net.lateral_movement"
	KindExfil     = "net.data_exfiltration"
	KindBeaconing = "net.beaconing"
)

// Network detector tuning. These bound the cheap pre-filters that
// decide whether an entity is even a *candidate* worth scoring — the
// statistical gate (z-score vs the tenant baseline) is what actually
// fires the alert. They are floors, not thresholds: an entity below
// these is never a candidate regardless of z-score, which keeps a
// cold-start baseline (still learning) from alerting on a single
// benign connection.
const (
	// minPortScanPorts is the smallest distinct-port fan-out from
	// one source that is even considered a scan candidate. Below
	// this the "scan" is statistically meaningless noise.
	minPortScanPorts = 10
	// minLateralFanout is the smallest distinct internal-destination
	// count that is considered lateral-movement candidate.
	minLateralFanout = 5
	// minBeaconSamples is the minimum number of connections to a
	// single (src,dst) pair required before a regularity score is
	// meaningful — you cannot call three packets "periodic".
	minBeaconSamples = 4
	// minExfilBytes is the smallest single-destination outbound
	// volume considered an exfil candidate (1 MiB). Below this the
	// z-score on a quiet tenant would fire on routine uploads.
	minExfilBytes = 1 << 20
)

// FlowEvent is one observed network flow (a connection or a
// flow-export record) within a collection window. The upstream
// collector batches these per window and hands the batch to
// NetworkDetector.Evaluate — mirroring how the baseline Service is
// fed pre-bucketed observations rather than raw events.
type FlowEvent struct {
	// Src / Dst are the flow endpoints.
	Src netip.Addr
	Dst netip.Addr
	// DstPort is the destination transport port (0 if not
	// applicable, e.g. ICMP — such flows are ignored by the
	// port-scan detector but still count for lateral / exfil).
	DstPort uint16
	// BytesOut is bytes sent Src→Dst in this flow. Used by the
	// exfiltration detector.
	BytesOut int64
	// At is the flow's timestamp (start of connection). Used by
	// the beaconing detector to measure inter-arrival regularity.
	At time.Time
}

// DestinationOracle answers "has this tenant talked to this
// destination before this window?". The exfiltration detector uses
// it to escalate large transfers to *new* destinations (the classic
// "first contact + big upload" exfil shape). It is optional: a nil
// oracle means every destination is treated as already-known, so
// exfil fires on volume alone.
//
// Implementations must be safe for concurrent use. Record is called
// for every destination observed in a window AFTER scoring, so the
// next window sees this window's destinations as known.
type DestinationOracle interface {
	// Seen reports whether dst was recorded for tenantID before now.
	Seen(tenantID uuid.UUID, dst netip.Addr) bool
	// Record marks dst as seen for tenantID at observedAt.
	Record(tenantID uuid.UUID, dst netip.Addr, observedAt time.Time)
}

// NetworkDetector turns a window of FlowEvents into typed anomaly
// alerts. It owns no per-flow state of its own — windows are passed
// in whole — so it is safe to share one instance across the process.
type NetworkDetector struct {
	det      *Detector
	oracle   DestinationOracle
	internal []netip.Prefix
	now      func() time.Time
}

// NewNetworkDetector builds a NetworkDetector around an existing
// baseline Detector (which supplies the estimator + the
// AlertEmitter). oracle may be nil (exfil fires on volume alone).
// extraInternal augments the built-in RFC1918 / loopback /
// link-local / ULA ranges with site-specific internal CIDRs (e.g.
// a CGNAT or a routed datacentre block) for the lateral-movement
// internal/internal classification.
func NewNetworkDetector(det *Detector, oracle DestinationOracle, extraInternal []netip.Prefix) *NetworkDetector {
	internal := append(defaultInternalPrefixes(), extraInternal...)
	return &NetworkDetector{
		det:      det,
		oracle:   oracle,
		internal: internal,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall-clock source (tests pin alert
// timestamps). No-op on nil.
func (n *NetworkDetector) SetClock(fn func() time.Time) {
	if fn != nil {
		n.now = fn
	}
}

// Evaluate scores one window of flows for tenantID and emits any
// resulting typed alerts. windowSeconds is the bucket size of the
// window (used to scope the baseline + stamp the alert window).
// Returns the alerts that were emitted (possibly empty). A nil
// AlertEmitter on the underlying Detector still scores + folds the
// baselines but emits nothing.
func (n *NetworkDetector) Evaluate(
	ctx context.Context,
	tenantID uuid.UUID,
	flows []FlowEvent,
	windowSeconds int,
) ([]repository.Alert, error) {
	if tenantID == uuid.Nil || windowSeconds <= 0 {
		return nil, repository.ErrInvalidArgument
	}

	feats := n.reduce(tenantID, flows)
	var alerts []repository.Alert

	score := func(dim, kind string, value float64, candidate bool, evidence map[string]any) error {
		obs := Observation{Value: value, At: n.windowEnd(flows)}
		res, err := n.det.observeFoldScore(ctx, tenantID, dim, windowSeconds, obs)
		if err != nil {
			return err
		}
		// Fire only when the entity cleared the candidate floor AND
		// the feature is a statistical outlier against the tenant's
		// learned norm AND the estimator is warm.
		if !candidate || !res.Warm || !res.AboveThreshold {
			return nil
		}
		if n.det.emit == nil {
			return nil
		}
		alert, err := n.emit(ctx, tenantID, kind, dim, windowSeconds, value, res, evidence)
		if err != nil {
			return err
		}
		alerts = append(alerts, alert)
		return nil
	}

	if err := score(DimPortScan, KindPortScan, float64(feats.portScan.ports),
		feats.portScan.ports >= minPortScanPorts, map[string]any{
			"source":         feats.portScan.src.String(),
			"distinct_ports": feats.portScan.ports,
		}); err != nil {
		return alerts, err
	}

	if err := score(DimLateral, KindLateral, float64(feats.lateral.dsts),
		feats.lateral.dsts >= minLateralFanout, map[string]any{
			"source":                feats.lateral.src.String(),
			"distinct_internal_dst": feats.lateral.dsts,
		}); err != nil {
		return alerts, err
	}

	newDst := n.oracle != nil && feats.exfil.dst.IsValid() && !n.oracle.Seen(tenantID, feats.exfil.dst)
	if err := score(DimExfil, KindExfil, float64(feats.exfil.bytes),
		feats.exfil.bytes >= minExfilBytes, map[string]any{
			"destination":     dstString(feats.exfil.dst),
			"bytes_out":       feats.exfil.bytes,
			"new_destination": newDst,
		}); err != nil {
		return alerts, err
	}

	if err := score(DimBeaconing, KindBeaconing, feats.beacon.regularity,
		feats.beacon.samples >= minBeaconSamples, map[string]any{
			"source":         feats.beacon.src.String(),
			"destination":    dstString(feats.beacon.dst),
			"connections":    feats.beacon.samples,
			"period_seconds": round2(feats.beacon.periodSeconds),
			"jitter_cv":      round2(feats.beacon.jitterCV),
			"regularity":     round2(feats.beacon.regularity),
		}); err != nil {
		return alerts, err
	}

	// Record this window's destinations so the next window's exfil
	// check can tell "new" from "returning".
	if n.oracle != nil {
		seen := make(map[netip.Addr]struct{}, len(flows))
		for i := range flows {
			d := flows[i].Dst
			if !d.IsValid() {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			n.oracle.Record(tenantID, d, flows[i].At)
		}
	}

	return alerts, nil
}

// emit builds the typed, entity-rich alert and routes it through the
// AlertEmitter. Severity escalates to critical at 1.5x threshold,
// matching the generic z-score path.
func (n *NetworkDetector) emit(
	ctx context.Context,
	tenantID uuid.UUID,
	kind, dimension string,
	windowSeconds int,
	value float64,
	res ScoreResult,
	entity map[string]any,
) (repository.Alert, error) {
	severity := repository.AlertSeverityWarning
	if res.MaxAbsZ >= res.Threshold*1.5 {
		severity = repository.AlertSeverityCritical
	}

	cur := res.Pre
	evidence := map[string]any{
		"z_welford":        res.ZWelford,
		"z_ewma":           res.ZEWMA,
		"max_abs_z":        res.MaxAbsZ,
		"threshold_z":      res.Threshold,
		"baseline_mean":    cur.Mean,
		"baseline_samples": cur.Samples,
		"window_seconds":   windowSeconds,
		"observed_value":   value,
	}
	for k, v := range entity {
		evidence[k] = v
	}
	evidenceJSON, _ := json.Marshal(evidence)

	stddev := cur.StdDev()
	if stddev == 0 || math.IsNaN(stddev) {
		stddev = cur.EWMAStdDev()
	}

	now := n.now()
	a := repository.Alert{
		TenantID:       tenantID,
		Kind:           kind,
		Severity:       severity,
		Dimension:      dimension,
		ObservedValue:  value,
		BaselineMean:   cur.Mean,
		BaselineStdDev: stddev,
		ZScore:         res.MaxAbsZ,
		WindowStart:    now.Add(-time.Duration(windowSeconds) * time.Second),
		WindowEnd:      now,
		WindowSeconds:  windowSeconds,
		Summary:        n.summary(kind, value, cur, res, entity),
		Evidence:       evidenceJSON,
		State:          repository.AlertStateOpen,
	}
	emitted, err := n.det.emit.Emit(ctx, tenantID, a)
	if err != nil {
		return repository.Alert{}, fmt.Errorf("network emit %s: %w", kind, err)
	}
	return emitted, nil
}

func (n *NetworkDetector) summary(
	kind string,
	value float64,
	cur repository.BaselineModel,
	res ScoreResult,
	entity map[string]any,
) string {
	switch kind {
	case KindPortScan:
		return fmt.Sprintf(
			"port scan: source %v hit %d distinct ports (mean %.1f, z=%.2fσ ≥ %.2fσ)",
			entity["source"], int(value), cur.Mean, res.MaxAbsZ, res.Threshold,
		)
	case KindLateral:
		return fmt.Sprintf(
			"lateral movement: source %v reached %d distinct internal hosts (mean %.1f, z=%.2fσ ≥ %.2fσ)",
			entity["source"], int(value), cur.Mean, res.MaxAbsZ, res.Threshold,
		)
	case KindExfil:
		tag := ""
		if nd, ok := entity["new_destination"].(bool); ok && nd {
			tag = " (new destination)"
		}
		return fmt.Sprintf(
			"data exfiltration: %.0f bytes outbound to %v%s (mean %.0f, z=%.2fσ ≥ %.2fσ)",
			value, entity["destination"], tag, cur.Mean, res.MaxAbsZ, res.Threshold,
		)
	case KindBeaconing:
		return fmt.Sprintf(
			"beaconing: %v→%v every ~%vs, jitter cv %v, regularity %.2f (z=%.2fσ ≥ %.2fσ)",
			entity["source"], entity["destination"], entity["period_seconds"],
			entity["jitter_cv"], value, res.MaxAbsZ, res.Threshold,
		)
	default:
		return fmt.Sprintf("%s: observed %.3f (z=%.2fσ ≥ %.2fσ)", kind, value, res.MaxAbsZ, res.Threshold)
	}
}

// --- window reduction ------------------------------------------------------

type portScanFeat struct {
	src   netip.Addr
	ports int
}

type lateralFeat struct {
	src  netip.Addr
	dsts int
}

type exfilFeat struct {
	dst   netip.Addr
	bytes int64
}

type beaconFeat struct {
	src           netip.Addr
	dst           netip.Addr
	samples       int
	periodSeconds float64
	jitterCV      float64
	regularity    float64
}

type windowFeatures struct {
	portScan portScanFeat
	lateral  lateralFeat
	exfil    exfilFeat
	beacon   beaconFeat
}

// reduce collapses a window of flows into the per-signal maxima. One
// pass builds the per-entity aggregates; a second pass over the
// (small) aggregate maps extracts the maximum for each signal.
func (n *NetworkDetector) reduce(_ uuid.UUID, flows []FlowEvent) windowFeatures {
	// src -> set of distinct dst ports (port scan)
	portsBySrc := map[netip.Addr]map[uint16]struct{}{}
	// src -> set of distinct internal dsts (lateral movement)
	internalDstBySrc := map[netip.Addr]map[netip.Addr]struct{}{}
	// dst -> total outbound bytes (exfil)
	bytesByDst := map[netip.Addr]int64{}
	// (src,dst) -> connection timestamps (beaconing)
	type pair struct{ src, dst netip.Addr }
	timesByPair := map[pair][]time.Time{}

	for i := range flows {
		f := flows[i]
		if !f.Src.IsValid() || !f.Dst.IsValid() {
			continue
		}
		if f.DstPort != 0 {
			set := portsBySrc[f.Src]
			if set == nil {
				set = map[uint16]struct{}{}
				portsBySrc[f.Src] = set
			}
			set[f.DstPort] = struct{}{}
		}
		if n.isInternal(f.Src) && n.isInternal(f.Dst) && f.Src != f.Dst {
			set := internalDstBySrc[f.Src]
			if set == nil {
				set = map[netip.Addr]struct{}{}
				internalDstBySrc[f.Src] = set
			}
			set[f.Dst] = struct{}{}
		}
		if f.BytesOut > 0 {
			bytesByDst[f.Dst] += f.BytesOut
		}
		if !n.isInternal(f.Dst) {
			p := pair{f.Src, f.Dst}
			timesByPair[p] = append(timesByPair[p], f.At)
		}
	}

	var feats windowFeatures

	for src, set := range portsBySrc {
		if len(set) > feats.portScan.ports {
			feats.portScan = portScanFeat{src: src, ports: len(set)}
		}
	}
	for src, set := range internalDstBySrc {
		if len(set) > feats.lateral.dsts {
			feats.lateral = lateralFeat{src: src, dsts: len(set)}
		}
	}
	for dst, b := range bytesByDst {
		if b > feats.exfil.bytes {
			feats.exfil = exfilFeat{dst: dst, bytes: b}
		}
	}
	for p, times := range timesByPair {
		reg, period, cv, ok := beaconRegularity(times)
		if !ok {
			continue
		}
		if reg > feats.beacon.regularity {
			feats.beacon = beaconFeat{
				src:           p.src,
				dst:           p.dst,
				samples:       len(times),
				periodSeconds: period,
				jitterCV:      cv,
				regularity:    reg,
			}
		}
	}

	return feats
}

// windowEnd returns the latest flow timestamp (the window's right
// edge) so the folded baseline's LastObservedAt is meaningful. Falls
// back to the detector clock when the window is empty / untimed.
func (n *NetworkDetector) windowEnd(flows []FlowEvent) time.Time {
	var latest time.Time
	for i := range flows {
		if flows[i].At.After(latest) {
			latest = flows[i].At
		}
	}
	if latest.IsZero() {
		return n.now()
	}
	return latest.UTC()
}

// --- beaconing regularity --------------------------------------------------

// beaconRegularity scores how periodic a series of connection
// timestamps is. It returns (regularity, periodSeconds, jitterCV,
// ok). regularity is in [0,1]: 1 means perfectly periodic (zero
// jitter), 0 means highly irregular. It is derived from the
// coefficient of variation (cv = stddev/mean) of the inter-arrival
// gaps: regularity = 1 / (1 + cv), which is the standard beaconing
// score used by flow-analysis tooling.
//
// ok is false when there are too few samples (< minBeaconSamples) or
// the mean gap is non-positive (all timestamps identical), in which
// case the caller skips the pair.
func beaconRegularity(times []time.Time) (regularity, periodSeconds, jitterCV float64, ok bool) {
	if len(times) < minBeaconSamples {
		return 0, 0, 0, false
	}
	sorted := make([]time.Time, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	gaps := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		gaps = append(gaps, sorted[i].Sub(sorted[i-1]).Seconds())
	}

	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean <= 0 {
		return 0, 0, 0, false
	}

	var sq float64
	for _, g := range gaps {
		d := g - mean
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(len(gaps)))
	cv := stddev / mean
	regularity = 1.0 / (1.0 + cv)
	return regularity, mean, cv, true
}

// --- internal-range classification -----------------------------------------

// defaultInternalPrefixes is the built-in set treated as "internal"
// for lateral-movement classification and beaconing's external-only
// filter: RFC1918 v4, loopback, link-local, plus IPv6 loopback,
// link-local (fe80::/10) and unique-local (fc00::/7).
func defaultInternalPrefixes() []netip.Prefix {
	raw := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		// These literals are compile-time constant + valid; a parse
		// failure is impossible, but skip rather than panic if a
		// future edit breaks one.
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (n *NetworkDetector) isInternal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	for _, p := range n.internal {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- small helpers ---------------------------------------------------------

func dstString(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

// --- in-memory destination oracle ------------------------------------------

// MemoryDestinationOracle is a process-local DestinationOracle with
// a TTL. A destination is "seen" if it was recorded within the TTL
// window. It is safe for concurrent use. Suitable for a single
// control-plane instance; a multi-instance deployment would back the
// oracle with a shared store, but the interface is the seam for that.
type MemoryDestinationOracle struct {
	ttl  time.Duration
	now  func() time.Time
	mu   sync.Mutex
	seen map[uuid.UUID]map[netip.Addr]time.Time
}

// NewMemoryDestinationOracle builds an oracle with the given TTL.
// A zero/negative TTL defaults to 24h.
func NewMemoryDestinationOracle(ttl time.Duration) *MemoryDestinationOracle {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &MemoryDestinationOracle{
		ttl:  ttl,
		now:  func() time.Time { return time.Now().UTC() },
		seen: map[uuid.UUID]map[netip.Addr]time.Time{},
	}
}

// SetClock overrides the wall-clock source (tests pin TTL
// expiry). No-op on nil.
func (o *MemoryDestinationOracle) SetClock(fn func() time.Time) {
	if fn != nil {
		o.mu.Lock()
		o.now = fn
		o.mu.Unlock()
	}
}

// Seen reports whether dst was recorded for tenantID within the TTL.
func (o *MemoryDestinationOracle) Seen(tenantID uuid.UUID, dst netip.Addr) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.seen[tenantID]
	if m == nil {
		return false
	}
	at, ok := m[dst]
	if !ok {
		return false
	}
	return o.now().Sub(at) <= o.ttl
}

// Record marks dst as seen for tenantID at observedAt.
func (o *MemoryDestinationOracle) Record(tenantID uuid.UUID, dst netip.Addr, observedAt time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.seen[tenantID]
	if m == nil {
		m = map[netip.Addr]time.Time{}
		o.seen[tenantID] = m
	}
	m[dst] = observedAt.UTC()
}
