// service.go implements the cold-tier replay service: the
// foundation for policy change simulation (PR B / Task 7).
//
// The worker.go file in this same package handles a DIFFERENT
// replay flow — draining the SNG_DLQ stream back to JetStream
// after a hot-path outage. That worker re-publishes envelopes
// onto their origin telemetry subject so the live pipeline
// re-processes them.
//
// This Service, by contrast, replays *cold-tier* (S3-sealed)
// envelopes against a pair of policy evaluators — the currently
// deployed policy and the proposed new bundle — and produces a
// deterministic impact report that summarises how many flows
// would change verdict, which devices/users would be affected,
// and a per-verdict transition matrix.
//
// Design constraints:
//
//   * Deterministic: every input fed through the same pair of
//     evaluators must produce the same ImpactReport. The
//     service must NOT introduce wall-clock variance, RNG, or
//     concurrency-ordering effects.
//
//   * Side-effect free: replay must NOT publish onto NATS, write
//     to ClickHouse, or otherwise mutate live state. The
//     downstream consumer is a UI / API that wants to show the
//     operator "if you approve this diff, here is what changes".
//
//   * Resumable: replay over a multi-day window across millions
//     of events must be checkpointable so an operator can pause
//     / resume without losing progress. Implementation defers
//     persistence to PR B (the simulation handler); this file
//     exposes the per-object iteration so the caller can persist
//     the cursor.
package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// DefaultReplayBatchSize is the default ObjectsPerStep on a
// replay run when ReplayOptions.ObjectsPerStep is zero. The
// value is tuned so a single Step() call holds at most ~32 MiB
// of decoded envelopes in memory (4 objects × ~8 MiB sealed,
// which decompresses to roughly 4× that in JSON-Lines form).
const DefaultReplayBatchSize = 4

// DefaultReplayMaxEvents is the safety cap on the number of
// envelopes processed in a single Replay call when the caller
// passes MaxEvents=0. Set high enough to cover a full day of
// telemetry for a busy tenant but low enough to prevent an
// open-ended scan from monopolising the worker.
const DefaultReplayMaxEvents = 1_000_000

// Errors surfaced by the Service.
var (
	// ErrNilReader is returned when NewService is called with a
	// nil ColdReader. The replay path has no fallback.
	ErrNilReader = errors.New("replay: cold reader is required")

	// ErrNilEvaluator is returned when Replay is called without
	// both a previous and a proposed evaluator. The whole point
	// of replay is to compare the two — running with only one
	// would produce a meaningless report.
	ErrNilEvaluator = errors.New("replay: both prev and next evaluators are required")

	// ErrEmptyTenant is returned when Replay is called with a
	// nil tenant UUID — the cold reader is partitioned on
	// tenant_id and a nil value would cross-contaminate the
	// query.
	ErrEmptyTenant = errors.New("replay: tenant id is required")

	// ErrTimeRange is returned when the (Since, Until) window
	// passed to Replay is empty or inverted.
	ErrTimeRange = errors.New("replay: empty or inverted time window")
)

// ColdReader is the slice of the S3 archiver API the replay
// service uses to enumerate and read sealed batches for a given
// tenant + day window.
//
// Implementations are typically backed by the s3.Archiver but
// the interface is decoupled so tests can substitute an
// in-memory fixture and an operator can plug in an alternative
// archive backend (e.g. Azure Blob, GCS).
type ColdReader interface {
	// ListSealedObjects returns the (dataKey, manifestKey) pairs
	// for every sealed batch falling within the [since, until]
	// window for the given tenant, ordered by sealed_at. An
	// empty result is a valid response; an error must be
	// surfaced to the caller.
	ListSealedObjects(ctx context.Context, tenant uuid.UUID, since, until time.Time) ([]SealedRef, error)

	// OpenSealedObject returns a reader for the JSON-Lines
	// payload of a sealed batch (already zstd-decompressed),
	// and the manifest metadata. Callers MUST Close() the
	// returned reader. The manifest is parsed from the
	// manifest.json sidecar and is the authoritative source of
	// truth for sealed_at + event_count.
	OpenSealedObject(ctx context.Context, ref SealedRef) (io.ReadCloser, SealedManifest, error)
}

// SealedRef identifies one sealed batch in the cold tier.
// Returned by ListSealedObjects; consumed by OpenSealedObject.
type SealedRef struct {
	DataKey     string
	ManifestKey string
}

// SealedManifest is the subset of the s3.sealedManifest fields
// the replay service consumes. Decoupled from the s3 package
// (and re-declared here) so callers do not need to depend on
// the s3 package's types to build a custom ColdReader.
type SealedManifest struct {
	Tenant       uuid.UUID
	EventCount   int
	RawSHA256    string
	SealedSHA256 string
	OpenedAt     time.Time
	SealedAt     time.Time
}

// PolicyEvaluator is the slice of the policy compiler used by
// the replay service. It must be deterministic: the same
// envelope must always yield the same verdict. Production
// implementations are typically a thin wrapper over a compiled
// policy bundle.
//
// Implementations MUST NOT mutate the envelope, write to any
// store, or publish to NATS. They MUST also be safe for
// concurrent use — replay calls Evaluate from the same
// goroutine sequentially but a future parallelisation step
// (PR B) will fan out across cores.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, env schema.Envelope) (schema.Verdict, error)
}

// VerdictTransition is one cell of the impact report's
// transition matrix: "this many flows moved from PrevVerdict to
// NextVerdict". Records with PrevVerdict == NextVerdict are
// included so the report shows total throughput, not just the
// changed slice.
type VerdictTransition struct {
	PrevVerdict schema.Verdict
	NextVerdict schema.Verdict
	Count       int
}

// ImpactReport summarises the replay run. All counters are
// inclusive of both unchanged AND changed verdicts so the
// report doubles as a coverage report.
type ImpactReport struct {
	// TenantID is the scope of the report.
	TenantID uuid.UUID
	// Window is the closed [Since, Until] interval the report
	// covers.
	Since time.Time
	Until time.Time
	// Total is the number of envelopes processed.
	Total int
	// Changed is the number of envelopes whose verdict changed
	// (PrevVerdict != NextVerdict).
	Changed int
	// Transitions is the verdict-change matrix. Keys are
	// {prev, next} pairs; counts include unchanged rows.
	Transitions []VerdictTransition
	// AffectedDevices is the set of device IDs that saw at
	// least one verdict change.
	AffectedDevices []uuid.UUID
	// AffectedSites is the set of site IDs (per envelope.SiteID)
	// that saw at least one verdict change. Sites are the
	// natural rollup for an operator-facing impact view because
	// the device → site map is many-to-one and operators
	// typically remediate at the site boundary (e.g. apply a
	// firewall override at edge_X rather than per-device).
	AffectedSites []uuid.UUID
	// ObjectsScanned is the count of sealed objects opened.
	// Useful for forensics — paired with Total it tells the
	// operator the average batch density.
	ObjectsScanned int
	// PrevErrors / NextErrors count evaluator failures by
	// side. A non-zero value means the corresponding policy
	// bundle returned an error for some envelope; the report
	// includes the affected envelopes in Total but not in
	// Transitions.
	PrevErrors int
	NextErrors int
	// StartedAt / FinishedAt bound the run for operator
	// observability. Pinned by Service.nowFunc so tests can
	// fix the clock.
	StartedAt  time.Time
	FinishedAt time.Time
}

// ReplayOptions tunes one Replay call. All fields are optional.
type ReplayOptions struct {
	// ObjectsPerStep caps the number of sealed objects opened
	// per inner iteration. Zero → DefaultReplayBatchSize.
	ObjectsPerStep int

	// MaxEvents caps the total envelopes processed in one
	// call. Zero → DefaultReplayMaxEvents. A run that hits the
	// cap stops cleanly and the report records the truncation
	// via Total == MaxEvents (the caller can detect by
	// comparing against the sum of manifest event_counts).
	MaxEvents int

	// Logger overrides the service's default logger for this
	// call. Useful when operator-driven runs need a per-run log
	// stream. Nil → use the service logger.
	Logger *slog.Logger
}

// Service is the cold-tier replay engine. Construct with
// NewService.
type Service struct {
	reader  ColdReader
	logger  *slog.Logger
	nowFunc func() time.Time

	// Run-state guards. Only one Replay call may proceed at a
	// time — the replay path holds a large in-memory event
	// buffer and running two replays concurrently would
	// trivially blow the worker's memory budget.
	mu      sync.Mutex
	running bool
}

// NewService constructs a Service. The ColdReader is required.
func NewService(reader ColdReader, logger *slog.Logger) (*Service, error) {
	if reader == nil {
		return nil, ErrNilReader
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		reader:  reader,
		logger:  logger,
		nowFunc: time.Now,
	}, nil
}

// Replay enumerates the cold tier for the given tenant + window,
// runs each envelope through BOTH evaluators, and produces a
// deterministic ImpactReport. The call is synchronous; callers
// who want to stream progress should plumb the operator-facing
// streaming via the Service's run-state hooks (added in PR B).
func (s *Service) Replay(
	ctx context.Context,
	tenant uuid.UUID,
	since, until time.Time,
	prev PolicyEvaluator,
	next PolicyEvaluator,
	opts ReplayOptions,
) (ImpactReport, error) {
	if tenant == uuid.Nil {
		return ImpactReport{}, ErrEmptyTenant
	}
	if prev == nil || next == nil {
		return ImpactReport{}, ErrNilEvaluator
	}
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return ImpactReport{}, ErrTimeRange
	}
	logger := opts.Logger
	if logger == nil {
		logger = s.logger
	}
	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = DefaultReplayMaxEvents
	}
	objectsPerStep := opts.ObjectsPerStep
	if objectsPerStep <= 0 {
		objectsPerStep = DefaultReplayBatchSize
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ImpactReport{}, errors.New("replay: another run is in progress")
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	report := ImpactReport{
		TenantID:  tenant,
		Since:     since.UTC(),
		Until:     until.UTC(),
		StartedAt: s.nowFunc().UTC(),
	}

	// Step 1: enumerate sealed objects.
	refs, err := s.reader.ListSealedObjects(ctx, tenant, since, until)
	if err != nil {
		return ImpactReport{}, fmt.Errorf("replay: list sealed: %w", err)
	}
	logger.Info("replay: sealed objects to scan",
		slog.String("tenant", tenant.String()),
		slog.Int("objects", len(refs)),
	)

	// Step 2: stream-decode each object, evaluating envelopes
	// through both bundles, accumulating the transition matrix.
	transitions := make(map[verdictPair]int)
	affectedDevices := make(map[uuid.UUID]struct{})
	affectedSites := make(map[uuid.UUID]struct{})

	// Process refs in batches of ObjectsPerStep. The per-object
	// work is identical to the prior unbatched version; the
	// outer batch boundary gives operator-visible progress
	// logging and a natural checkpoint boundary for PR B's
	// resumable simulator (the cursor persists at
	// "next batch start", not mid-object). The in-flight
	// envelope working set is bounded — a single batch holds
	// at most objectsPerStep × MaxEventsPerObject decoded
	// envelopes in memory (default 4 × 25,000 ≈ 100k rows,
	// well under a worker's GB budget at ~300 B per envelope).
scanLoop:
	for batchStart := 0; batchStart < len(refs); batchStart += objectsPerStep {
		if ctx.Err() != nil {
			break scanLoop
		}
		if report.Total >= maxEvents {
			break scanLoop
		}
		batchEnd := batchStart + objectsPerStep
		if batchEnd > len(refs) {
			batchEnd = len(refs)
		}
		logger.Debug("replay: batch start",
			slog.Int("batch_start", batchStart),
			slog.Int("batch_end", batchEnd),
			slog.Int("objects_per_step", objectsPerStep),
			slog.Int("total_objects", len(refs)))

		for _, ref := range refs[batchStart:batchEnd] {
			if ctx.Err() != nil {
				break scanLoop
			}
			body, _, err := s.reader.OpenSealedObject(ctx, ref)
			if err != nil {
				logger.Warn("replay: open sealed object",
					slog.String("data_key", ref.DataKey),
					slog.Any("error", err))
				continue
			}
			envs, decodeErr := decodeSealedBatch(body)
			_ = body.Close()
			if decodeErr != nil {
				// Partial decode is the right trade-off:
				// the archiver writes JSON-Lines with one
				// envelope per row, so a single corrupted
				// row in a 25k-row sealed object should
				// not blank-line the other 24,999 rows in
				// the impact report. The decoder returns
				// whatever rows it could parse alongside
				// the first error; surface the error via
				// a warn but keep the good rows.
				logger.Warn("replay: partial decode of sealed object",
					slog.String("data_key", ref.DataKey),
					slog.Int("partial_envs", len(envs)),
					slog.Any("error", decodeErr))
			}
			if len(envs) == 0 {
				continue
			}
			report.ObjectsScanned++

			for _, env := range envs {
				if ctx.Err() != nil {
					break scanLoop
				}
				if report.Total >= maxEvents {
					logger.Info("replay: MaxEvents reached",
						slog.Int("max", maxEvents))
					break scanLoop
				}
				report.Total++

				prevVerdict, prevErr := prev.Evaluate(ctx, env)
				nextVerdict, nextErr := next.Evaluate(ctx, env)
				if prevErr != nil {
					report.PrevErrors++
				}
				if nextErr != nil {
					report.NextErrors++
				}
				// An envelope that one side could not
				// evaluate is excluded from the transition
				// matrix — the matrix counts only resolved
				// transitions. The envelope is still in
				// Total so the operator sees the volume.
				if prevErr != nil || nextErr != nil {
					continue
				}
				transitions[verdictPair{prev: prevVerdict, next: nextVerdict}]++
				if prevVerdict != nextVerdict {
					report.Changed++
					affectedDevices[env.DeviceID] = struct{}{}
					if env.SiteID != nil {
						affectedSites[*env.SiteID] = struct{}{}
					}
				}
			}
		}
	}

	// Step 3: materialise the transition matrix in a stable
	// deterministic order so two runs over the same input
	// produce byte-identical ImpactReports.
	report.Transitions = sortedTransitions(transitions)
	report.AffectedDevices = sortedUUIDs(affectedDevices)
	report.AffectedSites = sortedUUIDs(affectedSites)
	report.FinishedAt = s.nowFunc().UTC()

	return report, nil
}

// IsRunning reports whether a Replay call is currently in
// progress. Useful for the admin handler to surface "another
// run is active" without taking the lock.
func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
