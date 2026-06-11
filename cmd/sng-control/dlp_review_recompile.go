package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// dlpEnforcementRecompileTimeout bounds a single tenant recompile so a
// stuck Compile cannot pin a worker goroutine indefinitely.
const dlpEnforcementRecompileTimeout = 30 * time.Second

// tenantCompileFunc recompiles and stores one tenant's policy bundles.
// It is the seam over policy.Service.Compile so the recompiler is
// testable without standing up the whole policy service.
type tenantCompileFunc func(ctx context.Context, tenantID uuid.UUID) error

// dlpEnforcementRecompiler closes the operator→edge feedback loop: when
// an operator blocks an AI-app DLP event in the HITL review queue, it
// recompiles that tenant's policy bundle so the freshly-recorded per-app
// block override (dlp.CompileEndpointBundle reads the blocked apps from
// the review queue) reaches the edge AI-app detector. It implements
// [dlpreview.BlockHook].
//
// Recompiles are asynchronous — the operator's request never waits on a
// Compile — and per-tenant serialised with trailing coalescing: while a
// tenant's recompile is running, further blocks mark it dirty and cause
// exactly one more recompile after the in-flight pass finishes.
// Serialisation prevents a lost update (a slow early Compile overwriting
// a newer bundle); coalescing caps load when an operator blocks several
// events in quick succession. Because the hook fires only after the
// block is durably committed, the trailing pass is guaranteed to start
// after the latest block and therefore observe it.
type dlpEnforcementRecompiler struct {
	compile tenantCompileFunc
	timeout time.Duration
	logger  *slog.Logger

	mu     sync.Mutex
	states map[uuid.UUID]*tenantCompileState
	wg     sync.WaitGroup
}

// tenantCompileState tracks whether an in-flight recompile for a tenant
// must run again to capture a block that arrived while it was running.
type tenantCompileState struct {
	dirty bool
}

func newDLPEnforcementRecompiler(compile tenantCompileFunc, logger *slog.Logger) *dlpEnforcementRecompiler {
	if logger == nil {
		logger = slog.Default()
	}
	return &dlpEnforcementRecompiler{
		compile: compile,
		timeout: dlpEnforcementRecompileTimeout,
		logger:  logger,
		states:  make(map[uuid.UUID]*tenantCompileState),
	}
}

var _ dlpreview.BlockHook = (*dlpEnforcementRecompiler)(nil)

// OnBlock schedules an asynchronous recompile of the tenant's bundle.
// The caller's context is intentionally not retained: the recompile
// runs on a detached, timeout-bounded context so it survives the
// operator's request returning.
func (r *dlpEnforcementRecompiler) OnBlock(_ context.Context, tenantID uuid.UUID, _ dlpreview.ReviewEvent) {
	if tenantID == uuid.Nil {
		return
	}
	r.mu.Lock()
	if st, running := r.states[tenantID]; running {
		// A recompile for this tenant is already running; mark it so it
		// runs once more after the in-flight pass, capturing this block.
		st.dirty = true
		r.mu.Unlock()
		return
	}
	r.states[tenantID] = &tenantCompileState{}
	r.wg.Add(1)
	r.mu.Unlock()
	go r.run(tenantID)
}

func (r *dlpEnforcementRecompiler) run(tenantID uuid.UUID) {
	defer r.wg.Done()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		err := r.compile(ctx, tenantID)
		cancel()
		if err != nil {
			r.logger.Warn("dlp review: enforcement recompile failed",
				slog.String("tenant", tenantID.String()), slog.Any("error", err))
		}

		r.mu.Lock()
		st := r.states[tenantID]
		if st != nil && st.dirty {
			// A block arrived during the pass; clear the flag and run
			// once more so its override reaches the bundle.
			st.dirty = false
			r.mu.Unlock()
			continue
		}
		delete(r.states, tenantID)
		r.mu.Unlock()
		return
	}
}

// Wait blocks until all in-flight recompiles finish or ctx is done,
// whichever comes first. It is called on shutdown so a block recorded
// just before exit still reaches the edge bundle.
func (r *dlpEnforcementRecompiler) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
