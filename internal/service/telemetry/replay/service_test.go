package replay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/replay"
)

// fakeColdReader is an in-memory ColdReader for the replay
// service tests. It owns a static set of sealed objects keyed
// by data key; ListSealedObjects + OpenSealedObject return
// those directly.
type fakeColdReader struct {
	mu      sync.Mutex
	objects map[string]fakeSealed
	openErr error
	listErr error
}

type fakeSealed struct {
	manifest replay.SealedManifest
	body     []byte
}

func newFakeColdReader() *fakeColdReader {
	return &fakeColdReader{objects: map[string]fakeSealed{}}
}

func (f *fakeColdReader) add(key string, manifest replay.SealedManifest, envs []schema.Envelope) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var buf bytes.Buffer
	for _, env := range envs {
		// Match the s3 archiver's per-row JSON-Lines shape:
		// `{"envelope": {...}, "raw_b64": "..."}`. Replay
		// only consumes the envelope field; raw_b64 may be
		// empty.
		raw, _ := json.Marshal(struct {
			Envelope schema.Envelope `json:"envelope"`
			RawB64   string          `json:"raw_b64,omitempty"`
		}{Envelope: env})
		buf.Write(raw)
		buf.WriteString("\n")
	}
	manifest.EventCount = len(envs)
	f.objects[key] = fakeSealed{manifest: manifest, body: buf.Bytes()}
}

func (f *fakeColdReader) ListSealedObjects(_ context.Context, _ uuid.UUID, _ time.Time, _ time.Time) ([]replay.SealedRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	refs := make([]replay.SealedRef, 0, len(f.objects))
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	// Sort keys so iteration order is deterministic — that
	// matches the production archiver which emits keys with a
	// time-encoded seal hash.
	sort.Strings(keys)
	for _, k := range keys {
		refs = append(refs, replay.SealedRef{DataKey: k, ManifestKey: k + ".manifest"})
	}
	return refs, nil
}

func (f *fakeColdReader) OpenSealedObject(_ context.Context, ref replay.SealedRef) (io.ReadCloser, replay.SealedManifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return nil, replay.SealedManifest{}, f.openErr
	}
	obj, ok := f.objects[ref.DataKey]
	if !ok {
		return nil, replay.SealedManifest{}, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(obj.body)), obj.manifest, nil
}

// staticEvaluator implements PolicyEvaluator by returning a
// fixed verdict for every envelope.
type staticEvaluator struct {
	verdict schema.Verdict
	err     error
}

func (s staticEvaluator) Evaluate(_ context.Context, _ schema.Envelope) (schema.Verdict, error) {
	return s.verdict, s.err
}

// classBasedEvaluator returns a verdict based on the
// envelope's event class — useful for asserting transitions on
// a mixed corpus.
type classBasedEvaluator struct {
	flowVerdict schema.Verdict
	dnsVerdict  schema.Verdict
}

func (c classBasedEvaluator) Evaluate(_ context.Context, env schema.Envelope) (schema.Verdict, error) {
	switch env.EventClass {
	case schema.EventClassFlow:
		return c.flowVerdict, nil
	case schema.EventClassDNS:
		return c.dnsVerdict, nil
	default:
		return schema.VerdictLog, nil
	}
}

func mkEnv(tenant, device uuid.UUID, site *uuid.UUID, class schema.EventClass) schema.Envelope {
	return schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       uuid.New(),
		TenantID:      tenant,
		DeviceID:      device,
		SiteID:        site,
		Timestamp:     time.Now().UTC(),
		EventClass:    class,
		Platform:      schema.PlatformLinux,
	}
}

// --- tests --------------------------------------------------------------

func TestService_NewService_ValidatesInputs(t *testing.T) {
	t.Parallel()
	if _, err := replay.NewService(nil, nil); !errors.Is(err, replay.ErrNilReader) {
		t.Fatalf("nil reader: got %v want ErrNilReader", err)
	}
	r := newFakeColdReader()
	if _, err := replay.NewService(r, nil); err != nil {
		t.Fatalf("default logger: unexpected err %v", err)
	}
}

func TestReplay_RejectsInvalidArgs(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	svc, err := replay.NewService(r, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}
	ctx := context.Background()

	if _, err := svc.Replay(ctx, uuid.Nil, time.Now().Add(-time.Hour), time.Now(), prev, next, replay.ReplayOptions{}); !errors.Is(err, replay.ErrEmptyTenant) {
		t.Errorf("nil tenant: got %v", err)
	}
	if _, err := svc.Replay(ctx, uuid.New(), time.Now(), time.Now().Add(-time.Hour), prev, next, replay.ReplayOptions{}); !errors.Is(err, replay.ErrTimeRange) {
		t.Errorf("inverted range: got %v", err)
	}
	if _, err := svc.Replay(ctx, uuid.New(), time.Now().Add(-time.Hour), time.Now(), nil, next, replay.ReplayOptions{}); !errors.Is(err, replay.ErrNilEvaluator) {
		t.Errorf("nil prev: got %v", err)
	}
	if _, err := svc.Replay(ctx, uuid.New(), time.Now().Add(-time.Hour), time.Now(), prev, nil, replay.ReplayOptions{}); !errors.Is(err, replay.ErrNilEvaluator) {
		t.Errorf("nil next: got %v", err)
	}
}

func TestReplay_HappyPath_AllChanged(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	device1 := uuid.New()
	device2 := uuid.New()
	siteA := uuid.New()
	envs := []schema.Envelope{
		mkEnv(tenant, device1, &siteA, schema.EventClassFlow),
		mkEnv(tenant, device2, &siteA, schema.EventClassFlow),
		mkEnv(tenant, device1, nil, schema.EventClassDNS),
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.Total != 3 || rep.Changed != 3 {
		t.Errorf("counters: Total=%d Changed=%d, want 3/3", rep.Total, rep.Changed)
	}
	if len(rep.AffectedDevices) != 2 {
		t.Errorf("affected devices: got %d want 2", len(rep.AffectedDevices))
	}
	if len(rep.AffectedSites) != 1 {
		t.Errorf("affected sites: got %d want 1 (siteA)", len(rep.AffectedSites))
	}
	if len(rep.Transitions) != 1 {
		t.Errorf("transitions: got %d, want 1 (allow→deny)", len(rep.Transitions))
	}
	if rep.Transitions[0].Count != 3 {
		t.Errorf("transition count: got %d want 3", rep.Transitions[0].Count)
	}
	if rep.ObjectsScanned != 1 {
		t.Errorf("objects scanned: got %d want 1", rep.ObjectsScanned)
	}
}

func TestReplay_HappyPath_NoneChanged(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := []schema.Envelope{
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
		mkEnv(tenant, uuid.New(), nil, schema.EventClassDNS),
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictAllow}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.Total != 2 || rep.Changed != 0 {
		t.Errorf("counters: Total=%d Changed=%d, want 2/0", rep.Total, rep.Changed)
	}
	if len(rep.AffectedDevices) != 0 {
		t.Errorf("affected devices: got %d want 0", len(rep.AffectedDevices))
	}
}

func TestReplay_TransitionMatrix(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	device := uuid.New()
	envs := []schema.Envelope{
		mkEnv(tenant, device, nil, schema.EventClassFlow), // flow
		mkEnv(tenant, device, nil, schema.EventClassFlow), // flow
		mkEnv(tenant, device, nil, schema.EventClassDNS),  // dns
		mkEnv(tenant, device, nil, schema.EventClassDNS),  // dns
		mkEnv(tenant, device, nil, schema.EventClassDNS),  // dns
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := classBasedEvaluator{flowVerdict: schema.VerdictAllow, dnsVerdict: schema.VerdictAllow}
	next := classBasedEvaluator{flowVerdict: schema.VerdictDeny, dnsVerdict: schema.VerdictAllow}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.Total != 5 || rep.Changed != 2 {
		t.Errorf("counters: Total=%d Changed=%d, want 5/2", rep.Total, rep.Changed)
	}
	// Two transitions: allow→allow (3 DNS) and allow→deny (2 flow).
	gotAllowAllow := 0
	gotAllowDeny := 0
	for _, tr := range rep.Transitions {
		switch {
		case tr.PrevVerdict == schema.VerdictAllow && tr.NextVerdict == schema.VerdictAllow:
			gotAllowAllow = tr.Count
		case tr.PrevVerdict == schema.VerdictAllow && tr.NextVerdict == schema.VerdictDeny:
			gotAllowDeny = tr.Count
		}
	}
	if gotAllowAllow != 3 {
		t.Errorf("allow→allow: got %d want 3", gotAllowAllow)
	}
	if gotAllowDeny != 2 {
		t.Errorf("allow→deny: got %d want 2", gotAllowDeny)
	}
}

func TestReplay_DeterministicOutput(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := []schema.Envelope{
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
		mkEnv(tenant, uuid.New(), nil, schema.EventClassDNS),
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := classBasedEvaluator{flowVerdict: schema.VerdictAllow, dnsVerdict: schema.VerdictAllow}
	next := classBasedEvaluator{flowVerdict: schema.VerdictDeny, dnsVerdict: schema.VerdictDeny}

	// Pin the [Since, Until] window so the report carries
	// fixed timestamps. The determinism contract covers the
	// fields the operator-facing report should reproduce
	// byte-identically; the StartedAt / FinishedAt clock
	// fields are explicitly zeroed below because those are
	// inherently per-run wall-clock values.
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	run := func() string {
		rep, err := svc.Replay(context.Background(), tenant,
			since, until,
			prev, next, replay.ReplayOptions{})
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		// Zero out the wall-clock fields so the report is
		// comparable across runs.
		rep.StartedAt = time.Time{}
		rep.FinishedAt = time.Time{}
		bs, _ := json.Marshal(rep)
		return string(bs)
	}
	r1 := run()
	r2 := run()
	if r1 != r2 {
		t.Fatalf("non-deterministic report:\n%s\nvs\n%s", r1, r2)
	}
}

func TestReplay_EvaluatorErrorsCounted(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := []schema.Envelope{
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow, err: errors.New("policy error")}
	next := staticEvaluator{verdict: schema.VerdictDeny}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.PrevErrors != 2 {
		t.Errorf("PrevErrors: got %d want 2", rep.PrevErrors)
	}
	if rep.NextErrors != 0 {
		t.Errorf("NextErrors: got %d want 0", rep.NextErrors)
	}
	// Errored envelopes are NOT in the transition matrix.
	if len(rep.Transitions) != 0 {
		t.Errorf("transitions: got %d want 0 (errored envelopes excluded)", len(rep.Transitions))
	}
	// But they ARE in Total so the operator sees the volume.
	if rep.Total != 2 {
		t.Errorf("Total: got %d want 2", rep.Total)
	}
}

func TestReplay_MaxEventsTruncates(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := make([]schema.Envelope, 50)
	for i := range envs {
		envs[i] = mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow)
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{MaxEvents: 10})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.Total != 10 {
		t.Errorf("Total: got %d want 10 (truncated)", rep.Total)
	}
}

func TestReplay_ContextCancellation(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := make([]schema.Envelope, 100)
	for i := range envs {
		envs[i] = mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow)
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	rep, err := svc.Replay(ctx, tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	// A pre-cancelled ctx should produce a zero-or-near-zero
	// report — the scan loop checks ctx.Err() at every step.
	if rep.Total > 5 {
		t.Errorf("Total under cancelled ctx: got %d, want <= 5", rep.Total)
	}
}

func TestReplay_DLQOpenErrorSkipped(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	r.openErr = errors.New("simulated open failure")
	r.add("data1", replay.SealedManifest{Tenant: tenant}, []schema.Envelope{
		mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow),
	})
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}

	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay should tolerate open errors: %v", err)
	}
	if rep.Total != 0 {
		t.Errorf("Total: got %d want 0 (object skip)", rep.Total)
	}
}

func TestReplay_ListErrorPropagated(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	r.listErr = errors.New("simulated list failure")
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}
	_, err := svc.Replay(context.Background(), uuid.New(),
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err == nil || !strings.Contains(err.Error(), "list sealed") {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestReplay_ConcurrentRunsRejected(t *testing.T) {
	t.Parallel()
	r := newFakeColdReader()
	tenant := uuid.New()
	envs := make([]schema.Envelope, 1000)
	for i := range envs {
		envs[i] = mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow)
	}
	r.add("data1", replay.SealedManifest{Tenant: tenant}, envs)
	svc, _ := replay.NewService(r, nil)

	// First run blocks inside the evaluator until released.
	releaseFirst := make(chan struct{})
	prev := &evalWithGate{verdict: schema.VerdictAllow, gate: releaseFirst}
	next := staticEvaluator{verdict: schema.VerdictDeny}
	firstDone := make(chan error, 1)
	go func() {
		_, err := svc.Replay(context.Background(), tenant,
			time.Now().Add(-24*time.Hour), time.Now(),
			prev, next, replay.ReplayOptions{})
		firstDone <- err
	}()
	// Spin until IsRunning flips true.
	for i := 0; i < 200; i++ {
		if svc.IsRunning() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !svc.IsRunning() {
		close(releaseFirst)
		t.Fatalf("service never entered running state")
	}
	// Second run while the first is in-flight must be rejected.
	_, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		staticEvaluator{verdict: schema.VerdictAllow},
		staticEvaluator{verdict: schema.VerdictDeny},
		replay.ReplayOptions{})
	if err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Errorf("concurrent run: expected in-progress error, got %v", err)
	}
	close(releaseFirst)
	<-firstDone
}

type evalWithGate struct {
	verdict schema.Verdict
	gate    chan struct{}
	once    sync.Once
}

func (e *evalWithGate) Evaluate(ctx context.Context, _ schema.Envelope) (schema.Verdict, error) {
	e.once.Do(func() { <-e.gate })
	return e.verdict, nil
}

func TestDecodeSealedBatch_TolerantOfMalformedLine(t *testing.T) {
	t.Parallel()
	// Hand-craft a JSON-Lines body with one bad row in the
	// middle. The decoder must skip the bad row and return the
	// good ones plus an error.
	tenant := uuid.New()
	good := mkEnv(tenant, uuid.New(), nil, schema.EventClassFlow)
	bs, _ := json.Marshal(struct {
		Envelope schema.Envelope `json:"envelope"`
	}{Envelope: good})
	body := string(bs) + "\n" +
		"this is not json\n" +
		string(bs) + "\n"

	r := newFakeColdReader()
	r.add("data1", replay.SealedManifest{Tenant: tenant}, nil)
	// Overwrite the body directly to inject the malformed line.
	r.objects["data1"] = fakeSealed{
		manifest: replay.SealedManifest{Tenant: tenant},
		body:     []byte(body),
	}
	svc, _ := replay.NewService(r, nil)
	prev := staticEvaluator{verdict: schema.VerdictAllow}
	next := staticEvaluator{verdict: schema.VerdictDeny}
	rep, err := svc.Replay(context.Background(), tenant,
		time.Now().Add(-24*time.Hour), time.Now(),
		prev, next, replay.ReplayOptions{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rep.Total != 2 {
		t.Errorf("Total: got %d want 2 (malformed row skipped)", rep.Total)
	}
}
