package s3

import (
	"bytes"
	"compress/gzip"
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

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

type fakeS3 struct {
	mu      sync.Mutex
	puts    []*s3.PutObjectInput
	bodies  map[string][]byte
	failOn  string
	failErr error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && strings.Contains(deref(in.Key), f.failOn) {
		return nil, f.failErr
	}
	body, _ := io.ReadAll(in.Body)
	if f.bodies == nil {
		f.bodies = map[string][]byte{}
	}
	f.bodies[deref(in.Key)] = body
	cp := *in
	cp.Body = bytes.NewReader(body) // for any later inspection
	f.puts = append(f.puts, &cp)
	return &s3.PutObjectOutput{}, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func mkEnv(tenant uuid.UUID, ts time.Time, class schema.EventClass) (schema.Envelope, []byte) {
	env := schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      tenant,
		DeviceID:      uuid.New(),
		Timestamp:     ts,
		EventClass:    class,
		Platform:      schema.PlatformWindows,
		Payload:       []byte(`{"ok":true}`),
	}
	raw := []byte(`{"raw":true}`)
	return env, raw
}

// TestWriter_FlushOnSize confirms that crossing the byte / event
// threshold triggers a synchronous flush via the size signal —
// the flush interval would normally take longer.
func TestWriter_FlushOnSize(t *testing.T) {
	t.Parallel()
	fake := &fakeS3{}
	w, err := New(fake, Config{
		Bucket:             "telemetry-bucket",
		Prefix:             "tel",
		FlushInterval:      time.Hour, // never via interval
		MaxBytesPerObject:  1 << 30,
		MaxEventsPerObject: 3,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop(context.Background()) })

	tnt := uuid.New()
	ts := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		env, raw := mkEnv(tnt, ts.Add(time.Duration(i)*time.Second), schema.EventClassFlow)
		if err := w.Archive(context.Background(), env, raw); err != nil {
			t.Fatalf("Archive: %v", err)
		}
	}
	// Wait for the flush goroutine to fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		n := len(fake.puts)
		fake.mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.puts) != 1 {
		t.Fatalf("expected 1 put, got %d", len(fake.puts))
	}
	put := fake.puts[0]
	if put.ContentEncoding == nil || *put.ContentEncoding != "gzip" {
		t.Errorf("expected gzip ContentEncoding")
	}
	key := deref(put.Key)
	for _, want := range []string{
		"tel/tenant=" + tnt.String(),
		"date=2025-06-01",
		"hour=12",
		"class=flow",
	} {
		if !strings.Contains(key, want) {
			t.Errorf("key %q missing %q", key, want)
		}
	}

	gzr, err := gzip.NewReader(bytes.NewReader(fake.bodies[key]))
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	body, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("read decompressed: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d:\n%s", len(lines), body)
	}
	var rec archiveRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}
	if rec.TenantID != tnt {
		t.Errorf("tenant mismatch: got %s, want %s", rec.TenantID, tnt)
	}
	if rec.EventClass != "flow" {
		t.Errorf("class mismatch: got %s", rec.EventClass)
	}
	if want := base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)); rec.PayloadB64 != want {
		t.Errorf("payload b64 mismatch: got %s, want %s", rec.PayloadB64, want)
	}
	if want := base64.StdEncoding.EncodeToString([]byte(`{"raw":true}`)); rec.RawB64 != want {
		t.Errorf("raw b64 mismatch: got %s, want %s", rec.RawB64, want)
	}
}

// TestWriter_PartitionedByTenantClass asserts that events for
// different (tenant, hour, class) tuples land in separate objects.
func TestWriter_PartitionedByTenantClass(t *testing.T) {
	t.Parallel()
	fake := &fakeS3{}
	w, err := New(fake, Config{
		Bucket:             "b",
		FlushInterval:      30 * time.Millisecond,
		MaxBytesPerObject:  1 << 30,
		MaxEventsPerObject: 1 << 30,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop(context.Background()) })

	tntA := uuid.New()
	tntB := uuid.New()
	ts := time.Date(2025, 6, 1, 12, 30, 0, 0, time.UTC)
	envs := []schema.Envelope{
		{SchemaVersion: 1, EventID: uuid.New(), TenantID: tntA, DeviceID: uuid.New(), Timestamp: ts, EventClass: schema.EventClassFlow, Platform: schema.PlatformWindows, Payload: []byte(`{}`)},
		{SchemaVersion: 1, EventID: uuid.New(), TenantID: tntA, DeviceID: uuid.New(), Timestamp: ts, EventClass: schema.EventClassDNS, Platform: schema.PlatformWindows, Payload: []byte(`{}`)},
		{SchemaVersion: 1, EventID: uuid.New(), TenantID: tntB, DeviceID: uuid.New(), Timestamp: ts, EventClass: schema.EventClassFlow, Platform: schema.PlatformWindows, Payload: []byte(`{}`)},
	}
	for _, e := range envs {
		if err := w.Archive(context.Background(), e, []byte(`raw`)); err != nil {
			t.Fatalf("Archive: %v", err)
		}
	}
	if err := w.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.puts) != 3 {
		t.Fatalf("expected 3 objects (1 per partition), got %d", len(fake.puts))
	}
	classKeys := map[string]bool{}
	for _, p := range fake.puts {
		k := deref(p.Key)
		classKeys[k] = true
	}
	for tnt, classes := range map[uuid.UUID][]string{
		tntA: {"flow", "dns"},
		tntB: {"flow"},
	} {
		for _, c := range classes {
			want := "tenant=" + tnt.String() + "/date=2025-06-01/hour=12/class=" + c
			ok := false
			for k := range classKeys {
				if strings.Contains(k, want) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("missing object for tenant=%s class=%s", tnt, c)
			}
		}
	}
}

// TestWriter_UploadFailureLeavesNoPartitionLeak ensures that an
// upload error does not leak partitions back into the live map
// (which would cause unbounded retry on the same broken object).
func TestWriter_UploadFailureLeavesNoPartitionLeak(t *testing.T) {
	t.Parallel()
	fake := &fakeS3{failOn: "broken", failErr: errors.New("simulated S3 outage")}
	w, err := New(fake, Config{
		Bucket:             "b",
		FlushInterval:      time.Hour,
		MaxBytesPerObject:  1 << 30,
		MaxEventsPerObject: 1,
		Prefix:             "broken",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop(context.Background()) })

	env, raw := mkEnv(uuid.New(), time.Now().UTC(), schema.EventClassFlow)
	if err := w.Archive(context.Background(), env, raw); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	// Wait for the flush goroutine.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if w.Stats().UploadFails > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := w.Stats()
	if st.UploadFails == 0 {
		t.Fatal("expected at least one upload fail")
	}
	if st.OpenPartitions != 0 {
		t.Errorf("expected open partitions to be drained, got %d", st.OpenPartitions)
	}
}
