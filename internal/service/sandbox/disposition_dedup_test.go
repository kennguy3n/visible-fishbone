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
