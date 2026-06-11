package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// startEmbeddedNATS boots an in-process JetStream-enabled NATS
// server bound to a random port with a per-test store dir, so
// parallel tests do not collide. Returns the connection + a
// JetStream context; both are torn down via t.Cleanup.
func startEmbeddedNATS(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()

	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		JetStream:      true,
		StoreDir:       filepath.Join(t.TempDir(), "jetstream"),
		HTTPPort:       -1,
		NoSigs:         true,
		MaxControlLine: 4096,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new nats server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("nats server not ready in 5s")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})

	nc, err := nats.Connect(srv.ClientURL(), nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	return nc, js
}

const testStreamPrefix = "SNG"

// setupEventsStream creates the events stream the posture-push
// consumer reads from and returns a publisher bound to it.
func setupEventsStream(t *testing.T, js jetstream.JetStream) *sngnats.Publisher {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := sngnats.EnsureStream(ctx, js, sngnats.StreamSpec{
		Name:     sngnats.StreamName(testStreamPrefix, sngnats.StreamSuffixEvents),
		Subjects: []string{"sng.*.events.>"},
	})
	if err != nil {
		t.Fatalf("ensure events stream: %v", err)
	}
	cfg := &config.NATS{StreamPrefix: testStreamPrefix, Partitions: 1, RequestTimeout: 2 * time.Second}
	return sngnats.NewPublisher(js, cfg, "test-agent")
}

// stubUpdater records UpdatePosture calls and returns a configurable
// error sequence.
type stubUpdater struct {
	mu    sync.Mutex
	calls []postureCall
	errs  []error // consumed front-to-back; nil tail means "no error"
}

type postureCall struct {
	tenantID uuid.UUID
	deviceID uuid.UUID
	posture  repository.Posture
}

func (s *stubUpdater) UpdatePosture(_ context.Context, tenantID, deviceID uuid.UUID, p repository.Posture) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, postureCall{tenantID, deviceID, p})
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		return err
	}
	return nil
}

func (s *stubUpdater) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubUpdater) lastCall() (postureCall, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return postureCall{}, false
	}
	return s.calls[len(s.calls)-1], true
}

// runConsumer starts the consumer on a background goroutine and
// returns a cancel func (also registered as cleanup).
func runConsumer(t *testing.T, c *identity.PosturePushConsumer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("consumer did not stop within 3s of cancel")
		}
	})
}

func publishPostureUpdate(t *testing.T, pub *sngnats.Publisher, upd identity.PostureUpdate, headerTenant string) {
	t.Helper()
	data, err := json.Marshal(upd)
	if err != nil {
		t.Fatalf("marshal posture update: %v", err)
	}
	headers := map[string]string{}
	if headerTenant != "" {
		headers[sngnats.HeaderTenantID] = headerTenant
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subject := sngnats.SubjectForEvent(upd.TenantID.String(), identity.PostureUpdatedEventKind)
	if err := pub.Publish(ctx, subject, data, sngnats.PublishOptions{Headers: headers}); err != nil {
		t.Fatalf("publish posture update: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func ptrBool(b bool) *bool { return &b }

func TestPosturePushAppliesAndTriggersReeval(t *testing.T) {
	t.Parallel()
	nc, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	deviceID := uuid.New()

	// Subscribe to the out-of-cycle re-evaluation trigger before
	// running the consumer so we never miss it.
	sub, err := nc.SubscribeSync(sngnats.SubjectForEvent(tenantID.String(), identity.ReevalDeviceEventKind))
	if err != nil {
		t.Fatalf("subscribe reeval: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	updater := &stubUpdater{}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID,
		DeviceID: deviceID,
		Posture:  repository.Posture{DiskEncrypted: ptrBool(false), OSVersion: "Win 11"},
	}, tenantID.String())

	waitFor(t, "UpdatePosture called", func() bool { return updater.callCount() == 1 })
	call, _ := updater.lastCall()
	if call.tenantID != tenantID || call.deviceID != deviceID {
		t.Fatalf("UpdatePosture got tenant=%s device=%s, want tenant=%s device=%s",
			call.tenantID, call.deviceID, tenantID, deviceID)
	}
	if call.posture.DiskEncrypted == nil || *call.posture.DiskEncrypted {
		t.Fatalf("posture not propagated: %+v", call.posture)
	}

	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("expected reeval trigger: %v", err)
	}
	var trig struct {
		TenantID uuid.UUID `json:"tenant_id"`
		DeviceID uuid.UUID `json:"device_id"`
	}
	if err := json.Unmarshal(msg.Data, &trig); err != nil {
		t.Fatalf("decode trigger: %v", err)
	}
	if trig.TenantID != tenantID || trig.DeviceID != deviceID {
		t.Fatalf("trigger got tenant=%s device=%s, want tenant=%s device=%s",
			trig.TenantID, trig.DeviceID, tenantID, deviceID)
	}
	if got := msg.Header.Get(sngnats.HeaderDeviceID); got != deviceID.String() {
		t.Fatalf("trigger device header = %q, want %q", got, deviceID.String())
	}
}

// TestPosturePushReevalDedupKeyReflectsCollectionInstant pins the
// dedup-key contract that lets a genuinely newer posture snapshot fire
// its own out-of-cycle re-evaluation instead of being collapsed into an
// earlier trigger inside the events stream's dedup window. Two distinct
// posture snapshots for the same device (distinct CollectedAt) must
// publish triggers with *distinct* JetStream dedup keys, each keyed on
// the collection instant; a snapshot without CollectedAt must fall back
// to the (tenant, device) key.
func TestPosturePushReevalDedupKeyReflectsCollectionInstant(t *testing.T) {
	t.Parallel()
	nc, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	deviceID := uuid.New()

	sub, err := nc.SubscribeSync(sngnats.SubjectForEvent(tenantID.String(), identity.ReevalDeviceEventKind))
	if err != nil {
		t.Fatalf("subscribe reeval: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	updater := &stubUpdater{}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	t1 := time.Unix(1_700_000_000, 0).UTC()
	t2 := t1.Add(30 * time.Second)
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: deviceID,
		Posture: repository.Posture{DiskEncrypted: ptrBool(false), CollectedAt: &t1},
	}, tenantID.String())
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: deviceID,
		Posture: repository.Posture{DiskEncrypted: ptrBool(false), CollectedAt: &t2},
	}, tenantID.String())

	waitFor(t, "both posture updates applied", func() bool { return updater.callCount() == 2 })

	wantFirst := fmt.Sprintf("reeval-%s-%s-%d", tenantID, deviceID, t1.UnixNano())
	wantSecond := fmt.Sprintf("reeval-%s-%s-%d", tenantID, deviceID, t2.UnixNano())

	keys := map[string]bool{}
	for i := 0; i < 2; i++ {
		msg, err := sub.NextMsg(5 * time.Second)
		if err != nil {
			t.Fatalf("expected reeval trigger %d: %v", i, err)
		}
		keys[msg.Header.Get(jetstream.MsgIDHeader)] = true
	}
	if !keys[wantFirst] || !keys[wantSecond] {
		t.Fatalf("dedup keys = %v, want both %q and %q (distinct per collection instant)",
			keys, wantFirst, wantSecond)
	}
}

func TestPosturePushTerminalErrorIsDropped(t *testing.T) {
	t.Parallel()
	nc, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	deviceID := uuid.New()

	sub, err := nc.SubscribeSync(sngnats.SubjectForEvent(tenantID.String(), identity.ReevalDeviceEventKind))
	if err != nil {
		t.Fatalf("subscribe reeval: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	// Device unknown -> terminal: the message must be dropped
	// (Term), not retried, and no trigger fired.
	updater := &stubUpdater{errs: []error{repository.ErrNotFound}}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: deviceID, Posture: repository.Posture{},
	}, "")

	waitFor(t, "UpdatePosture called once", func() bool { return updater.callCount() == 1 })
	// Give redelivery a chance — a terminal Term must NOT redeliver.
	time.Sleep(700 * time.Millisecond)
	if got := updater.callCount(); got != 1 {
		t.Fatalf("terminal error redelivered: UpdatePosture called %d times, want 1", got)
	}
	if _, err := sub.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("expected no reeval trigger on terminal error, got err=%v", err)
	}
}

func TestPosturePushTransientErrorRedelivers(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	deviceID := uuid.New()

	// First delivery fails transiently (DB blip), second succeeds.
	updater := &stubUpdater{errs: []error{errors.New("db unavailable")}}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: deviceID, Posture: repository.Posture{},
	}, "")

	waitFor(t, "UpdatePosture retried after transient error",
		func() bool { return updater.callCount() >= 2 })
}

func TestPosturePushBadPayloadDropped(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	updater := &stubUpdater{}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	// Garbage that is not a PostureUpdate, plus a well-formed
	// payload after it: the consumer must drop the first and still
	// process the second (no head-of-line block).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subject := sngnats.SubjectForEvent(tenantID.String(), identity.PostureUpdatedEventKind)
	if err := pub.Publish(ctx, subject, []byte("not json"), sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish garbage: %v", err)
	}
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: uuid.New(), Posture: repository.Posture{},
	}, "")

	waitFor(t, "good message processed past poison", func() bool { return updater.callCount() == 1 })
	time.Sleep(400 * time.Millisecond)
	if got := updater.callCount(); got != 1 {
		t.Fatalf("UpdatePosture called %d times, want exactly 1 (poison must be dropped)", got)
	}
}

func TestPosturePushTenantMismatchDropped(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	tenantID := uuid.New()
	updater := &stubUpdater{}
	c := identity.NewPosturePushConsumer(js, updater, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	// Header tenant disagrees with payload tenant -> drop without
	// applying, to avoid any cross-tenant posture write.
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenantID, DeviceID: uuid.New(), Posture: repository.Posture{},
	}, uuid.New().String())

	// Follow with a clean message we can wait on as a barrier.
	cleanTenant := uuid.New()
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: cleanTenant, DeviceID: uuid.New(), Posture: repository.Posture{},
	}, cleanTenant.String())

	waitFor(t, "clean message processed", func() bool {
		c, ok := updater.lastCall()
		return ok && c.tenantID == cleanTenant
	})
	if got := updater.callCount(); got != 1 {
		t.Fatalf("UpdatePosture called %d times, want 1 (mismatch must be dropped)", got)
	}
}

// TestPosturePushIntegrationWithService wires the real identity
// Service + in-memory device repo to confirm a pushed posture is
// persisted on the device record.
func TestPosturePushIntegrationWithService(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	store := memory.NewStore()
	tenant, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	devices := memory.NewDeviceRepository(store)
	dev, err := devices.Create(context.Background(), tenant.ID, repository.Device{
		Name: "laptop", Platform: repository.DevicePlatformWindows, PublicKeyEd25519: "k",
	})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	svc := identity.New(devices, memory.NewClaimTokenRepository(store), memory.NewAuditLogRepository(store), nil)
	c := identity.NewPosturePushConsumer(js, svc, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenant.ID,
		DeviceID: dev.ID,
		Posture:  repository.Posture{DiskEncrypted: ptrBool(true), OSVersion: "Win 11 23H2"},
	}, tenant.ID.String())

	waitFor(t, "device posture persisted", func() bool {
		got, err := devices.Get(context.Background(), tenant.ID, dev.ID)
		return err == nil && got.Posture.OSVersion == "Win 11 23H2" &&
			got.Posture.DiskEncrypted != nil && *got.Posture.DiskEncrypted
	})
}

func ptrU32(v uint32) *uint32 { return &v }

// TestPosturePushCarriesExpandedPostureSignals is the WS4 follow-on
// regression: the expanded ZTNA posture signals (EDR health, OS patch
// recency, AV state + signature age, certificate health) must survive
// the control-plane ingestion hop — publish → events stream → consumer
// → device record — so the evaluator's hard gates actually bite.
//
// Before `repository.Posture` carried these fields, `encoding/json`
// dropped the unknown keys on the way in, so a device that reported a
// killed EDR sensor or stale AV definitions persisted as if it had
// reported nothing. This drives the real wire path and asserts every
// signal round-trips onto the persisted record.
func TestPosturePushCarriesExpandedPostureSignals(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	pub := setupEventsStream(t, js)

	store := memory.NewStore()
	tenant, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	devices := memory.NewDeviceRepository(store)
	dev, err := devices.Create(context.Background(), tenant.ID, repository.Device{
		Name: "laptop", Platform: repository.DevicePlatformWindows, PublicKeyEd25519: "k",
	})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	svc := identity.New(devices, memory.NewClaimTokenRepository(store), memory.NewAuditLogRepository(store), nil)
	c := identity.NewPosturePushConsumer(js, svc, pub, testStreamPrefix, nil,
		identity.WithPosturePushFetch(16, 200*time.Millisecond))
	runConsumer(t, c)

	// A device whose EDR sensor was killed, AV definitions are 240h
	// stale, OS last patched 45 days ago, and identity cert is past
	// expiry — every expanded signal on its *deny* side.
	publishPostureUpdate(t, pub, identity.PostureUpdate{
		TenantID: tenant.ID,
		DeviceID: dev.ID,
		Posture: repository.Posture{
			OSVersion:                    "Win 11 23H2",
			EDRHealthy:                   ptrBool(false),
			OSPatchDaysSince:             ptrU32(45),
			AntivirusEnabled:             ptrBool(true),
			AntivirusDefinitionsAgeHours: ptrU32(240),
			CertificateHealth:            repository.CertificateHealthExpired,
		},
	}, tenant.ID.String())

	waitFor(t, "expanded posture signals persisted", func() bool {
		got, err := devices.Get(context.Background(), tenant.ID, dev.ID)
		if err != nil || got.Posture.EDRHealthy == nil {
			return false
		}
		p := got.Posture
		return !*p.EDRHealthy &&
			p.OSPatchDaysSince != nil && *p.OSPatchDaysSince == 45 &&
			p.AntivirusEnabled != nil && *p.AntivirusEnabled &&
			p.AntivirusDefinitionsAgeHours != nil && *p.AntivirusDefinitionsAgeHours == 240 &&
			p.CertificateHealth == repository.CertificateHealthExpired
	})
}
