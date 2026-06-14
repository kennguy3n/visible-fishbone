package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// stubEventSource is an in-memory RetroEventSource for tests: it
// returns the envelopes whose timestamp falls in [since, until) and
// whose class is requested, mirroring the ClickHouse Reader's
// window + IN-list filter.
type stubEventSource struct {
	events      []schema.Envelope
	err         error
	lastClasses []schema.EventClass
	lastTenant  uuid.UUID
	calls       int
}

func (s *stubEventSource) ListEvents(
	_ context.Context,
	tenantID uuid.UUID,
	classes []schema.EventClass,
	since, until time.Time,
	maxEvents int,
) ([]schema.Envelope, error) {
	s.calls++
	s.lastClasses = classes
	s.lastTenant = tenantID
	if s.err != nil {
		return nil, s.err
	}
	want := make(map[schema.EventClass]struct{}, len(classes))
	for _, c := range classes {
		want[c] = struct{}{}
	}
	out := make([]schema.Envelope, 0, len(s.events))
	for _, e := range s.events {
		if _, ok := want[e.EventClass]; !ok {
			continue
		}
		if e.Timestamp.Before(since) || !e.Timestamp.Before(until) {
			continue
		}
		out = append(out, e)
		if len(out) >= maxEvents {
			break
		}
	}
	return out, nil
}

func mustPack(t *testing.T, p schema.Payload) []byte {
	t.Helper()
	b, err := schema.PackPayload(p)
	if err != nil {
		t.Fatalf("pack payload: %v", err)
	}
	return b
}

func dnsEnvelope(t *testing.T, ts time.Time, query string) schema.Envelope {
	t.Helper()
	return schema.Envelope{
		EventID:    uuid.New(),
		DeviceID:   uuid.New(),
		Timestamp:  ts,
		EventClass: schema.EventClassDNS,
		Payload:    mustPack(t, schema.DNSEvent{Query: query, QType: "A", Verdict: schema.VerdictAllow}),
	}
}

func flowEnvelope(t *testing.T, ts time.Time, dstIP string) schema.Envelope {
	t.Helper()
	return schema.Envelope{
		EventID:    uuid.New(),
		DeviceID:   uuid.New(),
		Timestamp:  ts,
		EventClass: schema.EventClassFlow,
		Payload: mustPack(t, schema.FlowEvent{
			SrcIP: "10.0.0.1", DstIP: dstIP, Protocol: "tcp", Verdict: schema.VerdictAllow,
		}),
	}
}

func httpEnvelope(t *testing.T, ts time.Time, sni string) schema.Envelope {
	t.Helper()
	return schema.Envelope{
		EventID:    uuid.New(),
		DeviceID:   uuid.New(),
		Timestamp:  ts,
		EventClass: schema.EventClassHTTP,
		Payload: mustPack(t, schema.HTTPEvent{
			Method: "GET", Host: sni, SNI: sni, Verdict: schema.VerdictAllow,
		}),
	}
}

func storeSnapshot(iocs ...IOC) IOCSnapshot {
	s := NewIOCStore()
	s.Upsert(iocs...)
	return s.Snapshot()
}

func TestRetroHunter_MatchesDomainIPAndCIDR(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, base.Add(1*time.Minute), "malware-drop.example"),    // exact domain hit
		dnsEnvelope(t, base.Add(2*time.Minute), "c2.malware-drop.example"), // subdomain hit
		dnsEnvelope(t, base.Add(3*time.Minute), "clean.example"),           // miss
		flowEnvelope(t, base.Add(4*time.Minute), "203.0.113.10"),           // exact IP hit
		flowEnvelope(t, base.Add(5*time.Minute), "198.51.100.42"),          // CIDR containment hit
		flowEnvelope(t, base.Add(6*time.Minute), "192.0.2.1"),              // miss
		httpEnvelope(t, base.Add(7*time.Minute), "malware-drop.example"),   // host hit
	}}
	snap := storeSnapshot(
		mkIOC(IOCTypeDomain, "malware-drop.example", 0.9),
		mkIOC(IOCTypeIP, "203.0.113.10", 0.9),
		mkIOC(IOCTypeCIDR, "198.51.100.0/24", 0.9),
	)
	set := NewRetroIndicatorSet(snap, 0.5)

	h := NewRetroHunter(src)
	report, err := h.Hunt(context.Background(), uuid.New(), set,
		base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("Hunt: %v", err)
	}

	if report.EventsScanned != 7 {
		t.Errorf("EventsScanned = %d, want 7", report.EventsScanned)
	}
	if len(report.Hits) != 5 {
		t.Fatalf("Hits = %d, want 5: %+v", len(report.Hits), report.Hits)
	}
	if report.ByType[IOCTypeDomain] != 3 {
		t.Errorf("domain hits = %d, want 3", report.ByType[IOCTypeDomain])
	}
	if report.ByType[IOCTypeIP] != 1 {
		t.Errorf("ip hits = %d, want 1", report.ByType[IOCTypeIP])
	}
	if report.ByType[IOCTypeCIDR] != 1 {
		t.Errorf("cidr hits = %d, want 1", report.ByType[IOCTypeCIDR])
	}
	// Hits are ordered by timestamp ascending.
	for i := 1; i < len(report.Hits); i++ {
		if report.Hits[i].Timestamp.Before(report.Hits[i-1].Timestamp) {
			t.Fatalf("hits not sorted by timestamp: %+v", report.Hits)
		}
	}
	// The subdomain hit reports the apex indicator but the queried name.
	var sub *RetroHit
	for i := range report.Hits {
		if report.Hits[i].MatchedValue == "c2.malware-drop.example" {
			sub = &report.Hits[i]
		}
	}
	if sub == nil {
		t.Fatal("expected a subdomain hit on c2.malware-drop.example")
	}
	if sub.Indicator != "malware-drop.example" {
		t.Errorf("subdomain hit indicator = %q, want apex malware-drop.example", sub.Indicator)
	}
}

func TestRetroHunter_EmptySetSkipsSource(t *testing.T) {
	t.Parallel()
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, time.Now(), "malware-drop.example"),
	}}
	h := NewRetroHunter(src)
	set := NewRetroIndicatorSet(IOCSnapshot{}, 0.5)
	report, err := h.Hunt(context.Background(), uuid.New(), set,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Hunt: %v", err)
	}
	if src.calls != 0 {
		t.Errorf("event source queried %d times for an empty set, want 0", src.calls)
	}
	if len(report.Hits) != 0 {
		t.Errorf("Hits = %d, want 0", len(report.Hits))
	}
}

func TestRetroHunter_ConfidenceFloorExcludesIndicator(t *testing.T) {
	t.Parallel()
	base := time.Now().UTC()
	src := &stubEventSource{events: []schema.Envelope{
		dnsEnvelope(t, base, "low-conf.example"),
	}}
	snap := storeSnapshot(mkIOC(IOCTypeDomain, "low-conf.example", 0.3))
	// Floor above the indicator's confidence -> set is empty.
	set := NewRetroIndicatorSet(snap, 0.5)
	if !set.empty() {
		t.Fatalf("set should be empty when all indicators are below the floor")
	}
	h := NewRetroHunter(src)
	report, err := h.Hunt(context.Background(), uuid.New(), set,
		base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("Hunt: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Errorf("Hits = %d, want 0", len(report.Hits))
	}
}

func TestRetroHunter_OnlyScansConfiguredClasses(t *testing.T) {
	t.Parallel()
	src := &stubEventSource{}
	h := NewRetroHunter(src, WithRetroEventClasses(schema.EventClassDNS))
	snap := storeSnapshot(mkIOC(IOCTypeDomain, "malware-drop.example", 0.9))
	if _, err := h.Hunt(context.Background(), uuid.New(), NewRetroIndicatorSet(snap, 0.5),
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Hunt: %v", err)
	}
	if len(src.lastClasses) != 1 || src.lastClasses[0] != schema.EventClassDNS {
		t.Errorf("classes = %v, want [dns]", src.lastClasses)
	}
}

func TestRetroHunter_DecodeErrorsCounted(t *testing.T) {
	t.Parallel()
	base := time.Now().UTC()
	bad := schema.Envelope{
		EventID:    uuid.New(),
		DeviceID:   uuid.New(),
		Timestamp:  base,
		EventClass: schema.EventClassDNS,
		Payload:    []byte("not-msgpack"),
	}
	src := &stubEventSource{events: []schema.Envelope{bad}}
	snap := storeSnapshot(mkIOC(IOCTypeDomain, "malware-drop.example", 0.9))
	h := NewRetroHunter(src)
	report, err := h.Hunt(context.Background(), uuid.New(), NewRetroIndicatorSet(snap, 0.5),
		base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("Hunt: %v", err)
	}
	if report.DecodeErrors != 1 {
		t.Errorf("DecodeErrors = %d, want 1", report.DecodeErrors)
	}
	if len(report.Hits) != 0 {
		t.Errorf("Hits = %d, want 0", len(report.Hits))
	}
}

func TestRetroHunter_PropagatesSourceError(t *testing.T) {
	t.Parallel()
	src := &stubEventSource{err: errors.New("clickhouse down")}
	snap := storeSnapshot(mkIOC(IOCTypeDomain, "malware-drop.example", 0.9))
	h := NewRetroHunter(src)
	_, err := h.Hunt(context.Background(), uuid.New(), NewRetroIndicatorSet(snap, 0.5),
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error from event source")
	}
}

func TestRetroHunter_RejectsBadWindowAndTenant(t *testing.T) {
	t.Parallel()
	h := NewRetroHunter(&stubEventSource{})
	set := NewRetroIndicatorSet(storeSnapshot(mkIOC(IOCTypeDomain, "x.example", 0.9)), 0.5)
	now := time.Now()
	if _, err := h.Hunt(context.Background(), uuid.Nil, set, now.Add(-time.Hour), now); err == nil {
		t.Error("expected error for nil tenant")
	}
	if _, err := h.Hunt(context.Background(), uuid.New(), set, now, now); err == nil {
		t.Error("expected error for non-advancing window")
	}
}
