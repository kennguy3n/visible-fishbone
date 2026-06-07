package sandbox

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/sandbox/providers"
)

// blockingProvider counts Submit calls atomically and blocks each one
// on a release channel so a test can hold several submissions
// in-flight simultaneously and assert that singleflight collapsed
// them into a single provider call.
type blockingProvider struct {
	submitCalls atomic.Int32
	release     chan struct{}
}

func (b *blockingProvider) ID() string { return "blocking" }

func (b *blockingProvider) Submit(_ context.Context, _ providers.File) (providers.SubmitResult, error) {
	b.submitCalls.Add(1)
	<-b.release // hold the submission in-flight until released
	return providers.SubmitResult{
		SandboxID: "blk-id",
		Status:    providers.StatusComplete,
		Result: providers.PollResult{
			Status:         providers.StatusComplete,
			Classification: providers.ClassClean,
			Confidence:     1.0,
			AnalyzedAt:     time.Now().UTC(),
		},
	}, nil
}

func (b *blockingProvider) Poll(_ context.Context, _ string) (providers.PollResult, error) {
	return providers.PollResult{Status: providers.StatusComplete, Classification: providers.ClassClean}, nil
}

func TestSubmit_ConcurrentDedup(t *testing.T) {
	p := &blockingProvider{release: make(chan struct{})}
	svc, tid := newTestEnv(t, p)

	const n = 8
	var wg sync.WaitGroup
	results := make([]Verdict, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = svc.Submit(context.Background(), Submission{
				TenantID: tid, SHA256: testSHA256, Content: []byte("x"),
			}, nil)
		}(i)
	}
	close(start)
	// Give the goroutines a moment to all enter singleflight before
	// releasing the single provider submission they collapse into.
	time.Sleep(50 * time.Millisecond)
	close(p.release)
	wg.Wait()

	if got := p.submitCalls.Load(); got != 1 {
		t.Fatalf("expected provider Submit to be called exactly once, got %d", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("submit %d: %v", i, errs[i])
		}
		if results[i].Classification != ClassClean {
			t.Fatalf("submit %d: expected clean, got %s", i, results[i].Classification)
		}
	}
}

// ctxAwareProvider blocks Submit until released and then honours the
// context it was given: if that context was cancelled it returns the
// cancellation error, exactly as the real http.Client-backed
// providers do. It lets a test prove the singleflight leader's
// context is detached from any single caller's lifecycle.
type ctxAwareProvider struct {
	submitCalls atomic.Int32
	release     chan struct{}
}

func (c *ctxAwareProvider) ID() string { return "ctxaware" }

func (c *ctxAwareProvider) Submit(ctx context.Context, _ providers.File) (providers.SubmitResult, error) {
	c.submitCalls.Add(1)
	<-c.release
	if err := ctx.Err(); err != nil {
		return providers.SubmitResult{}, err
	}
	return providers.SubmitResult{
		SandboxID: "ctx-id",
		Status:    providers.StatusComplete,
		Result: providers.PollResult{
			Status:         providers.StatusComplete,
			Classification: providers.ClassClean,
			Confidence:     1.0,
			AnalyzedAt:     time.Now().UTC(),
		},
	}, nil
}

func (c *ctxAwareProvider) Poll(_ context.Context, _ string) (providers.PollResult, error) {
	return providers.PollResult{Status: providers.StatusComplete, Classification: providers.ClassClean}, nil
}

// TestSubmit_LeaderCancelDoesNotFailCoalesced verifies that when the
// caller that wins the singleflight has its context cancelled, the
// shared detonation still completes for the other coalesced callers
// (whose contexts remain valid). Before the WithoutCancel fix the
// leader's cancellation propagated to everyone.
func TestSubmit_LeaderCancelDoesNotFailCoalesced(t *testing.T) {
	p := &ctxAwareProvider{release: make(chan struct{})}
	svc, tid := newTestEnv(t, p)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var leaderErr, followerErr error
	var followerVerdict Verdict

	wg.Add(2)
	// Leader: enters the flight first and blocks in the provider.
	go func() {
		defer wg.Done()
		_, leaderErr = svc.Submit(leaderCtx, Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil)
	}()
	// Give the leader a moment to win the flight before the follower
	// coalesces onto it.
	time.Sleep(30 * time.Millisecond)
	go func() {
		defer wg.Done()
		followerVerdict, followerErr = svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil)
	}()
	time.Sleep(30 * time.Millisecond)

	// Cancel the leader's context while the shared submission is still
	// in flight, then let the provider return.
	cancelLeader()
	close(p.release)
	wg.Wait()

	if got := p.submitCalls.Load(); got != 1 {
		t.Fatalf("expected provider Submit called exactly once, got %d", got)
	}
	if leaderErr != nil {
		t.Fatalf("leader: detached context should not surface cancellation, got %v", leaderErr)
	}
	if followerErr != nil {
		t.Fatalf("follower: leader cancel must not fail a coalesced caller, got %v", followerErr)
	}
	if followerVerdict.Classification != ClassClean {
		t.Fatalf("follower: expected clean verdict, got %s", followerVerdict.Classification)
	}
}

func TestDisposition_FailClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (*Service, uuid.UUID)
		want  Disposition
		clean bool
	}{
		{
			name: "never submitted denies fail-closed",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				return newTestEnv(t, nil)
			},
			want:  DispositionDeny,
			clean: false,
		},
		{
			name: "submitted but unresolved is pending",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				// async provider leaves a pending (unknown) row.
				p := &stubProvider{syncResult: false}
				svc, tid := newTestEnv(t, p)
				if _, err := svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil); err != nil {
					t.Fatalf("submit: %v", err)
				}
				return svc, tid
			},
			want:  DispositionPending,
			clean: false,
		},
		{
			name: "resolved clean allows",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				p := &stubProvider{syncResult: true, classification: providers.ClassClean, score: 1.0}
				svc, tid := newTestEnv(t, p)
				if _, err := svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil); err != nil {
					t.Fatalf("submit: %v", err)
				}
				return svc, tid
			},
			want:  DispositionAllow,
			clean: true,
		},
		{
			name: "resolved malicious denies",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				p := &stubProvider{syncResult: true, classification: providers.ClassMalicious, score: 0.9}
				svc, tid := newTestEnv(t, p)
				if _, err := svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil); err != nil {
					t.Fatalf("submit: %v", err)
				}
				return svc, tid
			},
			want:  DispositionDeny,
			clean: false,
		},
		{
			name: "resolved suspicious denies (fail-closed)",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				p := &stubProvider{syncResult: true, classification: providers.ClassSuspicious, score: 0.5}
				svc, tid := newTestEnv(t, p)
				if _, err := svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil); err != nil {
					t.Fatalf("submit: %v", err)
				}
				return svc, tid
			},
			want:  DispositionDeny,
			clean: false,
		},
		{
			name: "provider error denies, not pending (terminal)",
			setup: func(t *testing.T) (*Service, uuid.UUID) {
				// Async submit leaves a pending (unknown) row; a poll
				// that the provider errors on makes the row terminal
				// (StatusError) while its classification stays unknown.
				// It must deny fail-closed, NOT pend — a pending reply
				// would have the caller re-poll a verdict that can
				// never resolve.
				p := &stubProvider{syncResult: false, pollStatus: providers.StatusError}
				svc, tid := newTestEnv(t, p)
				if _, err := svc.Submit(context.Background(), Submission{TenantID: tid, SHA256: testSHA256, Content: []byte("x")}, nil); err != nil {
					t.Fatalf("submit: %v", err)
				}
				if _, err := svc.Poll(context.Background(), tid, testSHA256); err != nil {
					t.Fatalf("poll: %v", err)
				}
				return svc, tid
			},
			want:  DispositionDeny,
			clean: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, tid := tc.setup(t)
			d, _, err := svc.Disposition(context.Background(), tid, testSHA256)
			if err != nil {
				t.Fatalf("Disposition: %v", err)
			}
			if d != tc.want {
				t.Fatalf("expected disposition %s, got %s", tc.want, d)
			}
			if d.Clean() != tc.clean {
				t.Fatalf("expected clean=%v, got %v", tc.clean, d.Clean())
			}
		})
	}
}

// TestDisposition_NeverSubmittedEchoesDigest verifies that a deny for a
// never-submitted sample still carries the requested digest in the
// returned Verdict (the disposition response renders v.SHA256, which
// must not be blank).
func TestDisposition_NeverSubmittedEchoesDigest(t *testing.T) {
	svc, tid := newTestEnv(t, nil)
	d, v, err := svc.Disposition(context.Background(), tid, testSHA256)
	if err != nil {
		t.Fatalf("Disposition: %v", err)
	}
	if d != DispositionDeny {
		t.Fatalf("expected deny, got %s", d)
	}
	if v.SHA256 != testSHA256 {
		t.Fatalf("expected verdict to echo digest %q, got %q", testSHA256, v.SHA256)
	}
	// The classification must be a valid enum member, not the empty
	// zero value: a never-submitted sample has no verdict, which is
	// exactly ClassUnknown. An empty string would render an invalid
	// enum in the API response.
	if v.Classification != ClassUnknown {
		t.Fatalf("expected ClassUnknown, got %q", v.Classification)
	}
	if !v.Classification.Valid() {
		t.Fatalf("classification %q is not a valid enum member", v.Classification)
	}
}
