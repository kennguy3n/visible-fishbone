package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// newTestWorker wires a worker against the memory store with a
// frozen clock for deterministic backoff math.
func newTestWorker(t *testing.T, now time.Time, cfg WorkerConfig) (*DeliveryWorker, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	store.SetClock(func() time.Time { return now })
	// Seed a tenant.
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t",
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	endpoints := memory.NewWebhookEndpointRepository(store)
	deliveries := memory.NewWebhookDeliveryRepository(store)
	w := NewDeliveryWorker(deliveries, endpoints, http.DefaultClient, cfg, nil)
	w.nowFunc = func() time.Time { return now }
	return w, store, tn.ID
}

func TestNextRetryAt_ExponentialUntilCap(t *testing.T) {
	t.Parallel()
	base := time.Now().UTC()
	w := &DeliveryWorker{cfg: WorkerConfig{
		BackoffBase: 10 * time.Second,
		BackoffMax:  5 * time.Minute,
	}}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 10 * time.Second},   // 2^0 * 10s
		{2, 20 * time.Second},   // 2^1
		{3, 40 * time.Second},   // 2^2
		{4, 80 * time.Second},   // 2^3
		{5, 160 * time.Second},  // 2^4
		{6, 5 * time.Minute},    // 2^5 = 320s, capped at 5m
		{20, 5 * time.Minute},   // capped
		{1000, 5 * time.Minute}, // exponent clamp + cap
	}
	for _, c := range cases {
		got := w.nextRetryAt(c.attempt, base).Sub(base)
		if got != c.want {
			t.Errorf("nextRetryAt(attempt=%d) = %v, want %v", c.attempt, got, c.want)
		}
	}
}

func TestNextRetryAt_NeverExceedsMaxOnOverflow(t *testing.T) {
	t.Parallel()
	base := time.Now().UTC()
	// Hostile config: base * 2^30 > BackoffMax → must clamp.
	w := &DeliveryWorker{cfg: WorkerConfig{
		BackoffBase: time.Hour,
		BackoffMax:  time.Hour,
	}}
	for _, attempt := range []int{1, 5, 50, 500} {
		got := w.nextRetryAt(attempt, base).Sub(base)
		if got != time.Hour {
			t.Errorf("attempt=%d delay=%v, want 1h cap", attempt, got)
		}
	}
}

func TestDeliver_SignsRequestWithHMACSHA256(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	var (
		receivedBody      []byte
		receivedSignature string
		receivedTimestamp string
		receivedEvent     string
		receivedDeliv     string
		receivedCT        string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedSignature = r.Header.Get("X-Sng-Signature")
		receivedTimestamp = r.Header.Get("X-Sng-Timestamp")
		receivedEvent = r.Header.Get("X-Sng-Event")
		receivedDeliv = r.Header.Get("X-Sng-Delivery-Id")
		receivedCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wkr, store, tenantID := newTestWorker(t, now, WorkerConfig{
		BatchSize: 10, MaxAttempts: 8,
		BackoffBase: 30 * time.Second, BackoffMax: time.Hour,
	})

	// Seed an active endpoint pointing at srv with a known secret.
	endpointRepo := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	secret := []byte("super-secret-32-byte-key-for-hmac")
	ep, err := endpointRepo.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: srv.URL, Events: []string{"tenant.created"},
		SigningSecret: secret,
		Status:        repository.WebhookEndpointStatusActive,
	})
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	payload := json.RawMessage(`{"hello":"world"}`)
	d, err := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID:  ep.ID,
		EventType:   "tenant.created",
		Payload:     payload,
		Status:      repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	})
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	processed, err := wkr.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}
	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}

	// Body must be exactly the payload we enqueued.
	if string(receivedBody) != string(payload) {
		t.Errorf("body = %q, want %q", string(receivedBody), string(payload))
	}
	if receivedEvent != "tenant.created" {
		t.Errorf("event header = %q", receivedEvent)
	}
	if receivedDeliv != d.ID.String() {
		t.Errorf("delivery id header = %q", receivedDeliv)
	}
	if receivedCT != "application/json" {
		t.Errorf("content-type = %q", receivedCT)
	}
	if receivedTimestamp != strconv.FormatInt(now.Unix(), 10) {
		t.Errorf("timestamp header = %q, want %d", receivedTimestamp, now.Unix())
	}

	// Independent recomputation with stdlib HMAC (not the worker's
	// post() helper) verifies the wire-format contract.
	expected := computeExpectedSignatureV1(t, secret, receivedTimestamp, receivedBody)
	if receivedSignature != expected {
		t.Errorf("signature = %q, want %q", receivedSignature, expected)
	}

	// The row must now be in delivered state.
	updated, err := deliveryRepo.Get(context.Background(), tenantID, d.ID)
	if err != nil {
		t.Fatalf("post-deliver get: %v", err)
	}
	if updated.Status != repository.WebhookDeliveryStatusDelivered {
		t.Errorf("status = %v", updated.Status)
	}
	if updated.Attempts != 1 {
		t.Errorf("attempts = %d", updated.Attempts)
	}
	if updated.ResponseStatus != http.StatusOK {
		t.Errorf("response status = %d", updated.ResponseStatus)
	}
}

// computeExpectedSignatureV1 reproduces the v1 signature format
// using a fresh stdlib hmac.New + hex encoding. The implementation
// under test uses the same stdlib primitives; using them here is
// not circular validation because the goal is to verify the
// *protocol* (timestamp.body, hex-encoded HMAC-SHA256, v1 prefix),
// not the correctness of stdlib HMAC.
func computeExpectedSignatureV1(t *testing.T, secret []byte, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write([]byte(timestamp + ".")); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	if _, err := mac.Write(body); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestDeliver_RetriesOn5xxThenSchedulesBackoff(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	wkr, store, tenantID := newTestWorker(t, now, WorkerConfig{
		BatchSize: 10, MaxAttempts: 5,
		BackoffBase: 30 * time.Second, BackoffMax: 10 * time.Minute,
	})
	endpointRepo := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	ep, err := endpointRepo.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: srv.URL, Events: []string{"tenant.created"},
		SigningSecret: []byte("k"),
		Status:        repository.WebhookEndpointStatusActive,
	})
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	d, err := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID: ep.ID, EventType: "tenant.created",
		Payload: json.RawMessage(`{}`), Status: repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	})
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	if _, err := wkr.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
	updated, err := deliveryRepo.Get(context.Background(), tenantID, d.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if updated.Status != repository.WebhookDeliveryStatusPending {
		t.Errorf("status = %v (expected pending after first 500)", updated.Status)
	}
	if updated.Attempts != 1 {
		t.Errorf("attempts = %d", updated.Attempts)
	}
	if updated.ResponseStatus != http.StatusInternalServerError {
		t.Errorf("response status = %d", updated.ResponseStatus)
	}
	// Next retry must be now + 30s (attempt=1 → 2^0 * 30s).
	wantNext := now.Add(30 * time.Second)
	if !updated.NextRetryAt.Equal(wantNext) {
		t.Errorf("next_retry_at = %v, want %v", updated.NextRetryAt, wantNext)
	}
}

func TestDeliver_ExhaustsAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "still broken", http.StatusBadGateway)
	}))
	defer srv.Close()

	wkr, store, tenantID := newTestWorker(t, now, WorkerConfig{
		BatchSize: 10, MaxAttempts: 3,
		BackoffBase: 30 * time.Second, BackoffMax: time.Hour,
	})
	endpointRepo := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	ep, _ := endpointRepo.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: srv.URL, Events: []string{"x"},
		SigningSecret: []byte("k"),
		Status:        repository.WebhookEndpointStatusActive,
	})
	d, _ := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID: ep.ID, EventType: "x",
		Payload: json.RawMessage(`{}`), Status: repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	})

	// Run ProcessPending repeatedly; each tick increments attempts.
	// We re-pull NextRetryAt forward via UpdateStatus(...) implicit
	// in the worker, but ListPending in the memory store filters
	// "next_retry_at > now". So after each failed attempt the row
	// would be skipped until our frozen clock catches up. To keep
	// the test deterministic, after each tick we reset NextRetryAt
	// back to `now` to simulate the clock advancing past the
	// scheduled retry.
	for i := 1; i <= 3; i++ {
		processed, err := wkr.ProcessPending(context.Background())
		if err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		if processed != 1 {
			t.Errorf("tick %d processed = %d, want 1", i, processed)
		}
		_ = deliveryRepo.UpdateStatus(context.Background(), tenantID, d.ID,
			repository.WebhookDeliveryStatusPending, i, "force-redrive", http.StatusBadGateway, now)
	}
	// 4th tick: the row IS still pending (we reset above), but the
	// worker should bump the attempt to 4, exceed MaxAttempts=3,
	// and mark exhausted.
	_, _ = wkr.ProcessPending(context.Background())
	final, err := deliveryRepo.Get(context.Background(), tenantID, d.ID)
	if err != nil {
		t.Fatalf("final get: %v", err)
	}
	if final.Status != repository.WebhookDeliveryStatusExhausted {
		t.Errorf("status = %v, want exhausted", final.Status)
	}
}

func TestDeliver_DisabledEndpointFailsImmediately(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	wkr, store, tenantID := newTestWorker(t, now, WorkerConfig{
		BatchSize: 10, MaxAttempts: 8,
		BackoffBase: 30 * time.Second, BackoffMax: time.Hour,
	})
	endpointRepo := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	ep, _ := endpointRepo.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: "https://nowhere.invalid/hook", Events: []string{"x"},
		SigningSecret: []byte("k"),
		Status:        repository.WebhookEndpointStatusDisabled,
	})
	d, _ := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID: ep.ID, EventType: "x",
		Payload: json.RawMessage(`{}`), Status: repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	})
	if _, err := wkr.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}
	got, _ := deliveryRepo.Get(context.Background(), tenantID, d.ID)
	if got.Status != repository.WebhookDeliveryStatusExhausted {
		t.Errorf("disabled endpoint → status = %v, want exhausted", got.Status)
	}
	if got.LastError != "endpoint disabled" {
		t.Errorf("last_error = %q", got.LastError)
	}
}

// secretStrippingEndpointRepo wraps a real endpoint repo and
// returns SigningSecret = nil on Get to simulate a row whose
// signing key has been wiped out-of-band (partial migration,
// manual DB edit, etc.). All other operations delegate verbatim.
type secretStrippingEndpointRepo struct {
	inner repository.WebhookEndpointRepository
}

func (r *secretStrippingEndpointRepo) Create(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	return r.inner.Create(ctx, tenantID, ep)
}

func (r *secretStrippingEndpointRepo) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookEndpoint, error) {
	ep, err := r.inner.Get(ctx, tenantID, id)
	if err != nil {
		return ep, err
	}
	ep.SigningSecret = nil
	return ep, nil
}

func (r *secretStrippingEndpointRepo) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookEndpoint], error) {
	return r.inner.List(ctx, tenantID, page)
}

func (r *secretStrippingEndpointRepo) Update(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	return r.inner.Update(ctx, tenantID, ep)
}

func (r *secretStrippingEndpointRepo) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.inner.Delete(ctx, tenantID, id)
}

func (r *secretStrippingEndpointRepo) ListActive(ctx context.Context, tenantID uuid.UUID, eventTypes []string) ([]repository.WebhookEndpoint, error) {
	return r.inner.ListActive(ctx, tenantID, eventTypes)
}

func TestDeliver_MissingSigningSecretFailsAttempt(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	store := memory.NewStore()
	store.SetClock(func() time.Time { return now })

	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t",
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := tn.ID

	innerEndpoints := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	ep, err := innerEndpoints.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: "https://nowhere.invalid/hook", Events: []string{"x"},
		SigningSecret: []byte("placeholder"),
		Status:        repository.WebhookEndpointStatusActive,
	})
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if _, err := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID: ep.ID, EventType: "x",
		Payload: json.RawMessage(`{}`), Status: repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	}); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	stripping := &secretStrippingEndpointRepo{inner: innerEndpoints}
	wkr := NewDeliveryWorker(deliveryRepo, stripping, http.DefaultClient, WorkerConfig{
		BatchSize: 10, MaxAttempts: 8,
		BackoffBase: 30 * time.Second, BackoffMax: time.Hour,
	}, nil)
	wkr.nowFunc = func() time.Time { return now }

	if _, err := wkr.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}
	// List rows (not ListPending — the row was rescheduled to now+30s
	// and would be filtered out of the pending window).
	page, err := deliveryRepo.List(context.Background(), tenantID, nil, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 row, got %d", len(page.Items))
	}
	got := page.Items[0]
	if got.Status != repository.WebhookDeliveryStatusPending {
		t.Errorf("status = %v, want pending (retryable)", got.Status)
	}
	if got.LastError != ErrSecretUnavailable.Error() {
		t.Errorf("last_error = %q, want %q", got.LastError, ErrSecretUnavailable.Error())
	}
	if got.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", got.Attempts)
	}
}

// TestDeliver_UsesConfiguredSignatureHeader is the regression test
// for the PR6 round-4 Devin Review finding: WEBHOOK_SIGNATURE_HEADER
// was loaded, defaulted, and validated at boot, but the previous
// WorkerConfig did not have a SignatureHeader field and the
// worker's post() helper hardcoded "X-Sng-Signature". An operator
// who set WEBHOOK_SIGNATURE_HEADER=X-Acme-Webhook-Sig got their
// value accepted at boot but silently ignored at delivery time;
// the downstream subscriber looked for the configured header,
// found it missing, and rejected the signature on every event.
//
// This test seeds a worker with a non-default SignatureHeader,
// observes the actual HTTP request, and asserts the configured
// header carried the v1 signature AND that the default header was
// NOT also set (so we'd catch the "set both" regression too).
func TestDeliver_UsesConfiguredSignatureHeader(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	const customHeader = "X-Acme-Webhook-Sig"

	var (
		gotCustom  string
		gotDefault string
		gotBody    []byte
		gotTS      string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get(customHeader)
		gotDefault = r.Header.Get("X-Sng-Signature")
		gotTS = r.Header.Get("X-Sng-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wkr, store, tenantID := newTestWorker(t, now, WorkerConfig{
		BatchSize: 1, MaxAttempts: 1,
		BackoffBase: time.Second, BackoffMax: time.Minute,
		SignatureHeader: customHeader,
	})

	endpointRepo := memory.NewWebhookEndpointRepository(store)
	deliveryRepo := memory.NewWebhookDeliveryRepository(store)
	secret := []byte("test-secret-for-custom-header-test")
	ep, err := endpointRepo.Create(context.Background(), tenantID, repository.WebhookEndpoint{
		URL: srv.URL, Events: []string{"tenant.created"},
		SigningSecret: secret,
		Status:        repository.WebhookEndpointStatusActive,
	})
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if _, err := deliveryRepo.Create(context.Background(), tenantID, repository.WebhookDelivery{
		EndpointID:  ep.ID,
		EventType:   "tenant.created",
		Payload:     json.RawMessage(`{"k":"v"}`),
		Status:      repository.WebhookDeliveryStatusPending,
		NextRetryAt: now,
	}); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	if _, err := wkr.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}

	if gotCustom == "" {
		t.Fatalf("custom signature header %q was not set; worker dropped operator config", customHeader)
	}
	if gotDefault != "" {
		t.Errorf("default header X-Sng-Signature also leaked = %q (worker should emit ONLY the configured header)",
			gotDefault)
	}
	want := computeExpectedSignatureV1(t, secret, gotTS, gotBody)
	if gotCustom != want {
		t.Errorf("%s = %q, want %q", customHeader, gotCustom, want)
	}
}

// TestWorkerConfig_DefaultsSignatureHeader confirms an empty
// SignatureHeader falls back to "X-SNG-Signature" so callers that
// don't set the field keep the historical behaviour.
func TestWorkerConfig_DefaultsSignatureHeader(t *testing.T) {
	t.Parallel()
	c := WorkerConfig{}
	c.defaults()
	if c.SignatureHeader != "X-SNG-Signature" {
		t.Errorf("SignatureHeader default = %q, want %q",
			c.SignatureHeader, "X-SNG-Signature")
	}
}
