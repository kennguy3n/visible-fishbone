// Package baseline_test — network_test pins the four network
// anomaly detectors. Each test warms a tenant baseline with benign
// windows (feature varies slightly so the estimator learns a
// non-zero variance) and then fires a single anomalous window,
// asserting the typed alert + entity evidence.
package baseline_test

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/baseline"
)

func intIP(n int) netip.Addr { return netip.MustParseAddr("10.0.0." + itoa(n)) }
func extIP(n int) netip.Addr { return netip.MustParseAddr("8.8.8." + itoa(n)) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func newNetDetector(t *testing.T, opts baseline.DetectorOptions, oracle baseline.DestinationOracle) (*baseline.NetworkDetector, *stubEmitter, uuid.UUID) {
	t.Helper()
	s, tnt := seedTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	svc := baseline.NewService(repo)
	emitter := &stubEmitter{}
	det := baseline.NewDetector(svc, emitter, opts)
	nd := baseline.NewNetworkDetector(det, oracle, nil)
	nd.SetClock(func() time.Time { return time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC) })
	return nd, emitter, tnt
}

var base = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// firstOfKind returns the first emitted alert of the given kind.
func firstOfKind(calls []repository.Alert, kind string) *repository.Alert {
	for i := range calls {
		if calls[i].Kind == kind {
			return &calls[i]
		}
	}
	return nil
}

func TestNetwork_PortScan(t *testing.T) {
	nd, emitter, tnt := newNetDetector(t, baseline.DetectorOptions{MinWarmupSamples: 8, WarningZScore: 3.0}, nil)

	// Warmup: one source touches 2-4 distinct ports per window.
	for i := 0; i < 15; i++ {
		ports := 2 + i%3
		var flows []baseline.FlowEvent
		for p := 0; p < ports; p++ {
			flows = append(flows, baseline.FlowEvent{
				Src: intIP(1), Dst: extIP(1), DstPort: uint16(1000 + p), At: base,
			})
		}
		if _, err := nd.Evaluate(ctx(), tnt, flows, 60); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}
	if len(emitter.calls) != 0 {
		t.Fatalf("alert during warmup: %+v", emitter.calls)
	}

	// Attack: one source sweeps 50 distinct ports.
	var scan []baseline.FlowEvent
	for p := 0; p < 50; p++ {
		scan = append(scan, baseline.FlowEvent{
			Src: intIP(7), Dst: extIP(2), DstPort: uint16(1 + p), At: base,
		})
	}
	alerts, err := nd.Evaluate(ctx(), tnt, scan, 60)
	if err != nil {
		t.Fatalf("attack: %v", err)
	}
	a := firstOfKind(alerts, baseline.KindPortScan)
	if a == nil {
		t.Fatalf("expected port_scan alert, got %+v", alerts)
	}
	if a.Dimension != baseline.DimPortScan {
		t.Fatalf("dimension = %s", a.Dimension)
	}
	var ev map[string]any
	if err := json.Unmarshal(a.Evidence, &ev); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if ev["source"] != "10.0.0.7" {
		t.Fatalf("evidence source = %v, want 10.0.0.7", ev["source"])
	}
	if ev["distinct_ports"].(float64) != 50 {
		t.Fatalf("distinct_ports = %v, want 50", ev["distinct_ports"])
	}
}

func TestNetwork_LateralMovement(t *testing.T) {
	nd, emitter, tnt := newNetDetector(t, baseline.DetectorOptions{MinWarmupSamples: 8, WarningZScore: 3.0}, nil)

	// Warmup: an internal source reaches 1-2 internal hosts.
	for i := 0; i < 15; i++ {
		dsts := 1 + i%2
		var flows []baseline.FlowEvent
		for d := 0; d < dsts; d++ {
			flows = append(flows, baseline.FlowEvent{
				Src: intIP(2), Dst: intIP(100 + d), DstPort: 445, At: base,
			})
		}
		if _, err := nd.Evaluate(ctx(), tnt, flows, 60); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}
	if c := len(emitter.calls); c != 0 {
		t.Fatalf("alert during warmup: %d", c)
	}

	// Attack: internal source sweeps 30 internal hosts (SMB spread).
	var lateral []baseline.FlowEvent
	for d := 0; d < 30; d++ {
		lateral = append(lateral, baseline.FlowEvent{
			Src: intIP(9), Dst: intIP(150 + d), DstPort: 445, At: base,
		})
	}
	alerts, err := nd.Evaluate(ctx(), tnt, lateral, 60)
	if err != nil {
		t.Fatalf("attack: %v", err)
	}
	a := firstOfKind(alerts, baseline.KindLateral)
	if a == nil {
		t.Fatalf("expected lateral_movement alert, got %+v", alerts)
	}
	var ev map[string]any
	_ = json.Unmarshal(a.Evidence, &ev)
	if ev["distinct_internal_dst"].(float64) != 30 {
		t.Fatalf("distinct_internal_dst = %v, want 30", ev["distinct_internal_dst"])
	}
}

func TestNetwork_DataExfiltration_NewDestination(t *testing.T) {
	oracle := baseline.NewMemoryDestinationOracle(24 * time.Hour)
	nd, _, tnt := newNetDetector(t, baseline.DetectorOptions{MinWarmupSamples: 8, WarningZScore: 3.0}, oracle)

	// Warmup: small outbound transfers (100-300 KiB) to a known dst.
	for i := 0; i < 15; i++ {
		bytesOut := int64(100<<10) + int64(i%3)*int64(100<<10)
		flows := []baseline.FlowEvent{{
			Src: intIP(3), Dst: extIP(1), DstPort: 443, BytesOut: bytesOut, At: base,
		}}
		if _, err := nd.Evaluate(ctx(), tnt, flows, 60); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}

	// Attack: 64 MiB to a brand-new destination.
	attack := []baseline.FlowEvent{{
		Src: intIP(3), Dst: extIP(200), DstPort: 443, BytesOut: 64 << 20, At: base,
	}}
	alerts, err := nd.Evaluate(ctx(), tnt, attack, 60)
	if err != nil {
		t.Fatalf("attack: %v", err)
	}
	a := firstOfKind(alerts, baseline.KindExfil)
	if a == nil {
		t.Fatalf("expected data_exfiltration alert, got %+v", alerts)
	}
	if a.Severity != repository.AlertSeverityCritical {
		t.Fatalf("severity = %s, want critical", a.Severity)
	}
	var ev map[string]any
	_ = json.Unmarshal(a.Evidence, &ev)
	if ev["destination"] != "8.8.8.200" {
		t.Fatalf("destination = %v", ev["destination"])
	}
	if nd2, ok := ev["new_destination"].(bool); !ok || !nd2 {
		t.Fatalf("new_destination = %v, want true", ev["new_destination"])
	}
}

func TestNetwork_Beaconing(t *testing.T) {
	nd, emitter, tnt := newNetDetector(t, baseline.DetectorOptions{MinWarmupSamples: 8, WarningZScore: 3.0}, nil)

	// Warmup: jittery external connections → moderate regularity that
	// varies window-to-window (so the baseline learns a non-zero
	// variance to score the beacon spike against).
	jitterPatterns := [][]int{
		{10, 25, 8, 30, 12},
		{5, 40, 7, 35, 9},
		{15, 20, 25, 10, 30},
	}
	for i := 0; i < 15; i++ {
		gaps := jitterPatterns[i%len(jitterPatterns)]
		flows := connectionsAt(intIP(4), extIP(1), gaps)
		if _, err := nd.Evaluate(ctx(), tnt, flows, 300); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}
	if c := len(emitter.calls); c != 0 {
		t.Fatalf("alert during warmup: %d (%+v)", c, emitter.calls)
	}

	// Attack: a near-perfect 60s beacon (zero jitter → regularity ~1).
	beacon := connectionsAt(intIP(4), extIP(50), []int{60, 60, 60, 60, 60, 60})
	alerts, err := nd.Evaluate(ctx(), tnt, beacon, 300)
	if err != nil {
		t.Fatalf("attack: %v", err)
	}
	a := firstOfKind(alerts, baseline.KindBeaconing)
	if a == nil {
		t.Fatalf("expected beaconing alert, got %+v", alerts)
	}
	var ev map[string]any
	_ = json.Unmarshal(a.Evidence, &ev)
	if ev["destination"] != "8.8.8.50" {
		t.Fatalf("destination = %v", ev["destination"])
	}
	if ev["regularity"].(float64) < 0.9 {
		t.Fatalf("regularity = %v, want >= 0.9", ev["regularity"])
	}
}

// connectionsAt builds a flow series src→dst whose inter-arrival
// gaps (seconds) are the given deltas. The first connection is at
// `base`; each subsequent one is the running sum later.
func connectionsAt(src, dst netip.Addr, gaps []int) []baseline.FlowEvent {
	flows := []baseline.FlowEvent{{Src: src, Dst: dst, DstPort: 443, At: base}}
	at := base
	for _, g := range gaps {
		at = at.Add(time.Duration(g) * time.Second)
		flows = append(flows, baseline.FlowEvent{Src: src, Dst: dst, DstPort: 443, At: at})
	}
	return flows
}

func TestNetwork_NoAlertDuringWarmup(t *testing.T) {
	nd, emitter, tnt := newNetDetector(t, baseline.DetectorOptions{MinWarmupSamples: 30, WarningZScore: 3.0}, nil)

	// A big scan on the very first window must NOT alert — the
	// estimator has not warmed up yet.
	var scan []baseline.FlowEvent
	for p := 0; p < 80; p++ {
		scan = append(scan, baseline.FlowEvent{Src: intIP(1), Dst: extIP(1), DstPort: uint16(1 + p), At: base})
	}
	alerts, err := nd.Evaluate(ctx(), tnt, scan, 60)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(alerts) != 0 || len(emitter.calls) != 0 {
		t.Fatalf("alert before warmup: %+v", alerts)
	}
}

func TestNetwork_InvalidArgs(t *testing.T) {
	nd, _, _ := newNetDetector(t, baseline.DetectorOptions{}, nil)
	if _, err := nd.Evaluate(ctx(), uuid.Nil, nil, 60); err == nil {
		t.Fatalf("expected error for nil tenant")
	}
	if _, err := nd.Evaluate(ctx(), uuid.New(), nil, 0); err == nil {
		t.Fatalf("expected error for zero window")
	}
}

func TestMemoryDestinationOracle_TTL(t *testing.T) {
	now := base
	o := baseline.NewMemoryDestinationOracle(time.Hour)
	o.SetClock(func() time.Time { return now })
	tnt := uuid.New()
	dst := extIP(1)

	if o.Seen(tnt, dst) {
		t.Fatalf("unseen dst reported seen")
	}
	o.Record(tnt, dst, now)
	if !o.Seen(tnt, dst) {
		t.Fatalf("recorded dst not seen")
	}
	now = now.Add(2 * time.Hour) // past TTL
	if o.Seen(tnt, dst) {
		t.Fatalf("dst seen after TTL expiry")
	}
}
