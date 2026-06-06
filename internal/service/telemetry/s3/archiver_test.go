package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// archiverFakeS3 implements ArchiverAPI for the archiver tests.
// Distinct from fakeS3 in writer_test.go because the archiver
// also calls GetObject.
type archiverFakeS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	putError error
	getError error
}

func newArchiverFakeS3() *archiverFakeS3 {
	return &archiverFakeS3{objects: map[string][]byte{}}
}

func (f *archiverFakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putError != nil {
		return nil, f.putError
	}
	body, _ := io.ReadAll(in.Body)
	f.objects[*in.Key] = body
	return &s3.PutObjectOutput{}, nil
}

func (f *archiverFakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getError != nil {
		return nil, f.getError
	}
	body, ok := f.objects[*in.Key]
	if !ok {
		return nil, errors.New("not found")
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (f *archiverFakeS3) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return b, ok
}

func (f *archiverFakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}

// --- helpers ------------------------------------------------------------

func makeEnvelope(t *testing.T, tenant uuid.UUID) (schema.Envelope, []byte) {
	t.Helper()
	env, err := schema.WrapFlowEvent(schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       uuid.New(),
		TenantID:      tenant,
		DeviceID:      uuid.New(),
		Timestamp:     time.Now().UTC(),
		Platform:      schema.PlatformLinux,
	}, "trusted_direct",
		schema.FlowEvent{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1, DstPort: 443, Protocol: "tcp",
			Verdict: schema.VerdictAllow, BytesIn: 100, BytesOut: 200, DurationMs: 5,
		})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return env, env.Payload
}

func newTestArchiver(t *testing.T, api ArchiverAPI, budget int64) *Archiver {
	t.Helper()
	a, err := NewArchiver(api, ArchiverConfig{
		Bucket:             "test-bucket",
		Prefix:             "test-archive",
		MaxBytesPerObject:  1 << 20,
		MaxEventsPerObject: 1000,
	}, StaticBudgetResolver{Bytes: budget}, nil)
	if err != nil {
		t.Fatalf("NewArchiver: %v", err)
	}
	return a
}

// --- tests --------------------------------------------------------------

func TestArchiver_BufferAndFlush(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)

	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)

	if err := a.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Nothing in S3 yet — Archive only buffers.
	if len(api.keys()) != 0 {
		t.Fatalf("expected no uploads before Flush, got %d", len(api.keys()))
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	keys := api.keys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 objects (data + manifest), got %d: %v", len(keys), keys)
	}
}

func TestArchiver_KeyLayout(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)
	// Pin the clock so the test asserts an exact key.
	a.nowFunc = func() time.Time { return time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC) }

	tenant := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	env, raw := makeEnvelope(t, tenant)

	if err := a.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var dataKey, manifestKey string
	for _, k := range api.keys() {
		if strings.HasSuffix(k, "data.zst") {
			dataKey = k
		}
		if strings.HasSuffix(k, "manifest.json") {
			manifestKey = k
		}
	}
	if dataKey == "" || manifestKey == "" {
		t.Fatalf("missing data/manifest key: dataKey=%q manifestKey=%q", dataKey, manifestKey)
	}
	wantPrefix := "test-archive/tenant_id=" + tenant.String() + "/yyyy=2026/mm=03/dd=14/seal="
	if !strings.HasPrefix(dataKey, wantPrefix) {
		t.Fatalf("data key prefix: got %q want prefix %q", dataKey, wantPrefix)
	}
	if !strings.HasPrefix(manifestKey, wantPrefix) {
		t.Fatalf("manifest key prefix: got %q want prefix %q", manifestKey, wantPrefix)
	}
}

func TestArchiver_BudgetRejection(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)
	// Set the budget below the size of a single envelope.
	a := newTestArchiver(t, api, int64(len(raw)-1))
	err := a.Archive(context.Background(), env, raw)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
	stats := a.Stats()
	if stats.BudgetRejections != 1 {
		t.Fatalf("BudgetRejections: got %d want 1", stats.BudgetRejections)
	}
	if stats.EventsArchived != 0 {
		t.Fatalf("EventsArchived should stay zero after a reject, got %d", stats.EventsArchived)
	}
}

func TestArchiver_BudgetIsPerTenantPerDay(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	tenantA := uuid.New()
	tenantB := uuid.New()
	envA, rawA := makeEnvelope(t, tenantA)
	envB, rawB := makeEnvelope(t, tenantB)
	// Budget just over the size of one envelope: enough for one
	// event per tenant per day.
	bigger := len(rawA)
	if len(rawB) > bigger {
		bigger = len(rawB)
	}
	a := newTestArchiver(t, api, int64(bigger))
	if err := a.Archive(context.Background(), envA, rawA); err != nil {
		t.Fatalf("first event A: %v", err)
	}
	if err := a.Archive(context.Background(), envB, rawB); err != nil {
		t.Fatalf("first event B: %v", err)
	}
	// Second event for tenant A should be rejected; tenant B
	// state must be unaffected.
	envA2, rawA2 := makeEnvelope(t, tenantA)
	if err := a.Archive(context.Background(), envA2, rawA2); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected tenant A budget rejection, got %v", err)
	}
}

func TestArchiver_StopFlushesPendingPartitions(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)
	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)
	if err := a.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if len(api.keys()) != 2 {
		t.Fatalf("expected stop to flush; got %d keys", len(api.keys()))
	}
	// Post-Stop Archive must return ErrArchiverClosed.
	if err := a.Archive(context.Background(), env, raw); !errors.Is(err, ErrArchiverClosed) {
		t.Fatalf("post-stop archive: expected ErrArchiverClosed, got %v", err)
	}
}

func TestArchiver_ManifestSchemaAndIntegrity(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)
	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)
	if err := a.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	var dataKey, manifestKey string
	for _, k := range api.keys() {
		if strings.HasSuffix(k, "data.zst") {
			dataKey = k
		}
		if strings.HasSuffix(k, "manifest.json") {
			manifestKey = k
		}
	}

	manifestBytes, _ := api.get(manifestKey)
	var manifest sealedManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("manifest unmarshal: %v", err)
	}
	if manifest.EventCount != 1 {
		t.Fatalf("EventCount: got %d want 1", manifest.EventCount)
	}
	if manifest.Tenant != tenant {
		t.Fatalf("Tenant: got %s want %s", manifest.Tenant, tenant)
	}
	if manifest.Compression != "zstd" {
		t.Fatalf("Compression: got %q want zstd", manifest.Compression)
	}
	if manifest.SealedSHA256 == "" || manifest.RawSHA256 == "" {
		t.Fatalf("manifest hashes empty: sealed=%q raw=%q", manifest.SealedSHA256, manifest.RawSHA256)
	}

	// Integrity check on untouched object → ok.
	if err := a.VerifyIntegrity(context.Background(), dataKey, manifestKey); err != nil {
		t.Fatalf("VerifyIntegrity (untouched): %v", err)
	}

	// Tamper with the data object → integrity must fail.
	api.mu.Lock()
	api.objects[dataKey] = append([]byte{}, "tampered"...)
	api.mu.Unlock()
	if err := a.VerifyIntegrity(context.Background(), dataKey, manifestKey); !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("VerifyIntegrity (tampered): expected ErrIntegrityViolation, got %v", err)
	}
}

func TestArchiver_RoundTripCompression(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)
	tenant := uuid.New()

	// Archive multiple events so the seal contains a real batch.
	want := 25
	for i := 0; i < want; i++ {
		env, raw := makeEnvelope(t, tenant)
		if err := a.Archive(context.Background(), env, raw); err != nil {
			t.Fatalf("archive[%d]: %v", i, err)
		}
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	var dataKey string
	for _, k := range api.keys() {
		if strings.HasSuffix(k, "data.zst") {
			dataKey = k
			break
		}
	}
	sealed, _ := api.get(dataKey)
	dec, err := zstd.NewReader(bytes.NewReader(sealed))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer dec.Close()
	raw, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	lines := bytes.Count(raw, []byte("\n"))
	if lines != want {
		t.Fatalf("decoded lines: got %d want %d", lines, want)
	}
	// Verify the first line decodes into a valid sealedEvent with
	// base64-encoded raw envelope bytes.
	first := bytes.SplitN(raw, []byte("\n"), 2)[0]
	var ev sealedEvent
	if err := json.Unmarshal(first, &ev); err != nil {
		t.Fatalf("decode first event: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(ev.RawB64); err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
}

func TestArchiver_MaxEventsPerObjectTriggersFlush(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a, err := NewArchiver(api, ArchiverConfig{
		Bucket:             "test-bucket",
		Prefix:             "p",
		MaxBytesPerObject:  1 << 30,
		MaxEventsPerObject: 3, // force seal at 3
	}, StaticBudgetResolver{Bytes: DefaultDailyBudgetBytes}, nil)
	if err != nil {
		t.Fatalf("NewArchiver: %v", err)
	}
	tenant := uuid.New()
	for i := 0; i < 5; i++ {
		env, raw := makeEnvelope(t, tenant)
		if err := a.Archive(context.Background(), env, raw); err != nil {
			t.Fatalf("archive[%d]: %v", i, err)
		}
	}
	// After 5 events with cap 3 we should see one auto-flush
	// (data + manifest). The remaining 2 are buffered until
	// Flush.
	keys := api.keys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after auto-flush, got %d: %v", len(keys), keys)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(api.keys()) != 4 {
		t.Fatalf("expected 4 keys after manual flush, got %d", len(api.keys()))
	}
}

func TestArchiver_RejectsZeroTenant(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	a := newTestArchiver(t, api, DefaultDailyBudgetBytes)
	env := schema.Envelope{TenantID: uuid.Nil}
	if err := a.Archive(context.Background(), env, []byte("x")); err == nil {
		t.Fatalf("expected error for zero tenant")
	}
}

// stubResidencyGuard lets the test drive the residency decision and
// records the tenant it was asked about.
type stubResidencyGuard struct {
	err     error
	calls   int
	lastTID uuid.UUID
}

func (g *stubResidencyGuard) Check(_ context.Context, tenantID uuid.UUID) error {
	g.calls++
	g.lastTID = tenantID
	return g.err
}

func TestArchiver_ResidencyGateRejectsCrossRegion(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	guard := &stubResidencyGuard{err: errors.New("residency: cross-region write rejected")}
	a, err := NewArchiver(api, ArchiverConfig{
		Bucket:    "eu-bucket",
		Residency: guard,
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewArchiver: %v", err)
	}

	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)
	if err := a.Archive(context.Background(), env, raw); err == nil {
		t.Fatal("expected residency rejection, got nil")
	}
	if guard.calls != 1 || guard.lastTID != tenant {
		t.Fatalf("guard not consulted with tenant: calls=%d tid=%s", guard.calls, guard.lastTID)
	}
	// Nothing buffered: a later Flush must upload nothing.
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(api.keys()) != 0 {
		t.Fatalf("rejected event must not be buffered or uploaded, got %d objects", len(api.keys()))
	}
	if got := a.Stats().ResidencyRejections; got != 1 {
		t.Fatalf("ResidencyRejections = %d, want 1", got)
	}
}

func TestArchiver_ResidencyGateAllowsSameRegion(t *testing.T) {
	t.Parallel()
	api := newArchiverFakeS3()
	guard := &stubResidencyGuard{err: nil}
	a, err := NewArchiver(api, ArchiverConfig{Bucket: "ap-bucket", Residency: guard}, nil, nil)
	if err != nil {
		t.Fatalf("NewArchiver: %v", err)
	}
	tenant := uuid.New()
	env, raw := makeEnvelope(t, tenant)
	if err := a.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("permitted write should archive, got %v", err)
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(api.keys()) != 2 {
		t.Fatalf("expected data + manifest upload, got %d", len(api.keys()))
	}
}

func TestNewArchiver_ValidatesInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewArchiver(nil, ArchiverConfig{Bucket: "b"}, nil, nil); err == nil {
		t.Fatalf("nil api should error")
	}
	if _, err := NewArchiver(newArchiverFakeS3(), ArchiverConfig{}, nil, nil); err == nil {
		t.Fatalf("empty bucket should error")
	}
}
