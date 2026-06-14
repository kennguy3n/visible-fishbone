package ai

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// blockingProvider is a test LLMProvider whose Complete blocks until
// released, recording max observed concurrency and per-tenant dispatch
// order so tests can assert the pool's concurrency cap and fairness.
type blockingProvider struct {
	release  chan struct{} // each Complete waits for one receive/close
	mu       sync.Mutex
	inflight int
	maxSeen  int
	order    []string // tenant tag, in the order Complete was entered
	calls    int
}

func newBlockingProvider() *blockingProvider {
	return &blockingProvider{release: make(chan struct{})}
}

func (b *blockingProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	b.mu.Lock()
	b.inflight++
	if b.inflight > b.maxSeen {
		b.maxSeen = b.inflight
	}
	b.calls++
	b.order = append(b.order, req.Prompt)
	b.mu.Unlock()

	select {
	case <-b.release:
	case <-ctx.Done():
		b.dec()
		return LLMResponse{}, ctx.Err()
	}
	b.dec()
	return LLMResponse{Text: "ok", ModelID: "test", TokenCount: 1}, nil
}

func (b *blockingProvider) dec() {
	b.mu.Lock()
	b.inflight--
	b.mu.Unlock()
}

func (b *blockingProvider) maxConcurrency() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxSeen
}

func (b *blockingProvider) dispatchOrder() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.order))
	copy(out, b.order)
	return out
}

// echoProvider returns immediately, echoing a fixed response. Used for
// pass-through and error-propagation tests.
type echoProvider struct {
	err   error
	calls atomic.Int64
}

func (e *echoProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	e.calls.Add(1)
	if e.err != nil {
		return LLMResponse{}, e.err
	}
	return LLMResponse{Text: req.Prompt, ModelID: "echo", TokenCount: 1}, nil
}

func ctxFor(t uuid.UUID) context.Context {
	return ContextWithTenantID(context.Background(), t)
}

func TestInferencePool_DisabledIsPassthrough(t *testing.T) {
	inner := &echoProvider{}
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: false}, nil)
	defer p.Close()

	resp, err := p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: "hi"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "hi" {
		t.Fatalf("want echoed prompt, got %q", resp.Text)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("want 1 inner call, got %d", got)
	}
	// A disabled pool must not record scheduling metrics.
	if snap := p.Metrics().Snapshot(); snap.Admitted != 0 {
		t.Fatalf("disabled pool should not admit; got %+v", snap)
	}
}

func TestInferencePool_PropagatesErrorAndResponse(t *testing.T) {
	wantErr := errors.New("backend down")
	inner := &echoProvider{err: wantErr}
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: 2}, nil)
	defer p.Close()

	_, err := p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: "x"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("want backend error propagated, got %v", err)
	}
	if snap := p.Metrics().Snapshot(); snap.Errors != 1 || snap.Completed != 0 {
		t.Fatalf("want errors=1 completed=0, got %+v", snap)
	}
}

func TestInferencePool_ConcurrencyCapEnforced(t *testing.T) {
	inner := newBlockingProvider()
	const capN = 3
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: capN, MaxQueuePerTenant: 100}, nil)
	defer p.Close()

	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		tenant := uuid.New()
		go func() {
			defer wg.Done()
			_, _ = p.Complete(ctxFor(tenant), LLMRequest{Prompt: "p"})
		}()
	}

	// Wait until the cap is saturated, then release everything.
	deadline := time.After(2 * time.Second)
	for inner.maxConcurrency() < capN {
		select {
		case <-deadline:
			t.Fatalf("never reached concurrency cap; max seen %d", inner.maxConcurrency())
		case <-time.After(time.Millisecond):
		}
	}
	close(inner.release)
	wg.Wait()

	if got := inner.maxConcurrency(); got > capN {
		t.Fatalf("concurrency cap exceeded: saw %d > %d", got, capN)
	}
	snap := p.Metrics().Snapshot()
	if snap.Admitted != n || snap.Completed != n {
		t.Fatalf("want admitted=completed=%d, got %+v", n, snap)
	}
	if snap.PeakInflight > capN {
		t.Fatalf("peak inflight %d exceeds cap %d", snap.PeakInflight, capN)
	}
}

// TestInferencePool_FairAcrossTenants verifies no tenant is starved: a
// single backend slot draining several tenants' queues must rotate
// across tenants rather than serving one tenant's whole backlog first.
//
// A "blocker" request pins the single concurrency slot until every
// tenant has fully enqueued, so admission starts from a clean,
// fully-populated ring and is then fully serialized — making the
// dispatch order deterministic round-robin.
func TestInferencePool_FairAcrossTenants(t *testing.T) {
	inner := newBlockingProvider()
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: 1, MaxQueuePerTenant: 100}, nil)
	defer p.Close()

	// Pin the slot with a blocker so nothing else can be admitted yet.
	var bwg sync.WaitGroup
	bwg.Add(1)
	go func() {
		defer bwg.Done()
		_, _ = p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: "Z"})
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Inflight == 1 })

	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	tags := map[uuid.UUID]string{tenants[0]: "A", tenants[1]: "B", tenants[2]: "C"}
	const perTenant = 4

	var wg sync.WaitGroup
	// Enqueue tenant A's whole backlog first, then B, then C, to bias
	// FIFO toward A. A fair scheduler must still interleave them.
	for ti, tn := range tenants {
		for i := 0; i < perTenant; i++ {
			wg.Add(1)
			tn := tn
			go func() {
				defer wg.Done()
				_, _ = p.Complete(ctxFor(tn), LLMRequest{Prompt: tags[tn]})
			}()
		}
		want := (ti + 1) * perTenant
		waitFor(t, func() bool {
			return int(p.Metrics().Snapshot().Queued) >= want
		})
	}

	// Release the blocker, then drain one request at a time. With a
	// single slot, each release frees exactly one in-flight call and the
	// dispatcher admits the next tenant in rotation.
	total := len(tenants) * perTenant
	for i := 0; i < total+1; i++ { // +1 for the blocker
		inner.release <- struct{}{}
	}
	wg.Wait()
	bwg.Wait()

	order := inner.dispatchOrder()
	if len(order) != total+1 {
		t.Fatalf("want %d dispatches, got %d (%v)", total+1, len(order), order)
	}
	// Strip the blocker (always first) and assert perfect round-robin
	// across the three tenants: no tenant served twice in a row, and
	// each served exactly perTenant times.
	order = order[1:]
	counts := map[string]int{}
	maxRun, runTag, run := 0, "", 0
	prev := ""
	for _, tag := range order {
		counts[tag]++
		if tag == prev {
			run++
		} else {
			run = 1
			prev = tag
		}
		if run > maxRun {
			maxRun, runTag = run, tag
		}
	}
	if maxRun > 1 {
		t.Fatalf("unfair dispatch: tenant %q served %d in a row (order %v)", runTag, maxRun, order)
	}
	for _, tag := range []string{"A", "B", "C"} {
		if counts[tag] != perTenant {
			t.Fatalf("tenant %q served %d times, want %d (order %v)", tag, counts[tag], perTenant, order)
		}
	}
}

func TestInferencePool_QueueFullRejects(t *testing.T) {
	inner := newBlockingProvider()
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: 1, MaxQueuePerTenant: 2}, nil)
	defer p.Close()

	tenant := uuid.New()
	var wg sync.WaitGroup
	submit := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Complete(ctxFor(tenant), LLMRequest{Prompt: "p"})
		}()
	}
	// First request takes the single slot (dequeued from the queue).
	submit()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Inflight == 1 })
	// Two more fill the per-tenant queue (depth 2).
	submit()
	submit()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Queued == 2 })

	// A further request for the same tenant must be shed immediately.
	_, err := p.Complete(ctxFor(tenant), LLMRequest{Prompt: "overflow"})
	if !errors.Is(err, ErrPoolBusy) {
		t.Fatalf("want ErrPoolBusy, got %v", err)
	}

	close(inner.release)
	wg.Wait()
	if snap := p.Metrics().Snapshot(); snap.Rejected != 1 {
		t.Fatalf("want rejected=1, got %+v", snap)
	}
}

func TestInferencePool_ContextCancelWithdraws(t *testing.T) {
	inner := newBlockingProvider()
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: 1, MaxQueuePerTenant: 100}, nil)
	defer p.Close()

	// Occupy the single slot with a blocking request.
	busy := uuid.New()
	var bwg sync.WaitGroup
	bwg.Add(1)
	go func() {
		defer bwg.Done()
		_, _ = p.Complete(ctxFor(busy), LLMRequest{Prompt: "busy"})
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Inflight == 1 })

	// Enqueue a second request, then cancel it while it waits.
	ctx, cancel := context.WithCancel(ctxFor(uuid.New()))
	done := make(chan error, 1)
	go func() {
		_, err := p.Complete(ctx, LLMRequest{Prompt: "waiter"})
		done <- err
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Queued == 1 })
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}
	waitFor(t, func() bool { return p.Metrics().Snapshot().Queued == 0 })
	if snap := p.Metrics().Snapshot(); snap.Cancelled != 1 {
		t.Fatalf("want cancelled=1, got %+v", snap)
	}

	close(inner.release)
	bwg.Wait()
}

func TestInferencePool_WaitTimeout(t *testing.T) {
	inner := newBlockingProvider()
	p := NewInferencePool(inner, InferencePoolConfig{
		Enabled:           true,
		MaxConcurrent:     1,
		MaxQueuePerTenant: 100,
		MaxWait:           50 * time.Millisecond,
	}, nil)
	defer p.Close()

	// Occupy the slot.
	busy := uuid.New()
	var bwg sync.WaitGroup
	bwg.Add(1)
	go func() {
		defer bwg.Done()
		_, _ = p.Complete(ctxFor(busy), LLMRequest{Prompt: "busy"})
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Inflight == 1 })

	// This one should time out in the queue.
	_, err := p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: "slow"})
	if !errors.Is(err, ErrPoolWaitTimeout) {
		t.Fatalf("want ErrPoolWaitTimeout, got %v", err)
	}
	if snap := p.Metrics().Snapshot(); snap.WaitTimeouts != 1 {
		t.Fatalf("want wait_timeouts=1, got %+v", snap)
	}

	close(inner.release)
	bwg.Wait()
}

func TestInferencePool_CloseReleasesQueuedWaiters(t *testing.T) {
	inner := newBlockingProvider()
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true, MaxConcurrent: 1, MaxQueuePerTenant: 100}, nil)

	busy := uuid.New()
	var bwg sync.WaitGroup
	bwg.Add(1)
	go func() {
		defer bwg.Done()
		_, _ = p.Complete(ctxFor(busy), LLMRequest{Prompt: "busy"})
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Inflight == 1 })

	// Queue a waiter, then Close the pool — the waiter must be released
	// with ErrPoolClosed rather than blocking forever.
	done := make(chan error, 1)
	go func() {
		_, err := p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: "waiter"})
		done <- err
	}()
	waitFor(t, func() bool { return p.Metrics().Snapshot().Queued == 1 })

	// Close while the waiter is still queued and the slot is still held
	// by the in-flight call, so the waiter is released via closedCh with
	// ErrPoolClosed. Freeing the slot first (close(inner.release) before
	// Close) would let the dispatcher admit the waiter and complete it
	// with a nil error, racing the assertion on a loaded host.
	p.Close()
	close(inner.release) // let the in-flight call finish

	select {
	case err := <-done:
		if !errors.Is(err, ErrPoolClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("want ErrPoolClosed for queued waiter, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued waiter not released on Close")
	}
	bwg.Wait()

	// Close is idempotent.
	p.Close()
}

func TestInferencePool_NoGoroutineLeakOnClose(t *testing.T) {
	inner := &echoProvider{}
	p := NewInferencePool(inner, InferencePoolConfig{Enabled: true}, nil)
	for i := 0; i < 50; i++ {
		_, _ = p.Complete(ctxFor(uuid.New()), LLMRequest{Prompt: fmt.Sprintf("r%d", i)})
	}
	p.Close()
	// The dispatcher goroutine must have exited.
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher goroutine did not exit after Close")
	}
}
