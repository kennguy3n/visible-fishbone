// Package s3 implements the cold-path telemetry archive sink
// backed by S3 (or any S3-compatible object store: MinIO, R2, GCS
// with the S3 endpoint, etc.). The writer batches incoming
// envelopes per-prefix into gzip-compressed JSON-Lines objects
// keyed by tenant, hour, and event class, then uploads each
// object with the AWS SDK v2 multipart manager so a flush of a
// large batch is split across concurrent PUTs.
//
// Object key format:
//
//	{prefix}/tenant={tenant_id}/date={YYYY-MM-DD}/hour={HH}/class={event_class}/{flush_id}.jsonl.gz
//
// One file per (tenant, hour, class, flush) — this keeps replay-by-
// tenant cheap (no scan of the whole bucket) and avoids the
// "lots of tiny files" anti-pattern by accumulating events until a
// size or interval trigger fires.
//
// Each line is a single envelope encoded as JSON, with the raw
// MessagePack payload base64-stamped so a downstream pipeline
// (Athena, ClickHouse-via-S3-engine, manual operator inspection)
// can decode it without msgpack-aware tooling. The line format is
// the operator-facing archive contract; do not change it without
// a versioning bump.
package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// DefaultFlushInterval is the maximum age of a buffered partition
// before the writer uploads it.
const DefaultFlushInterval = 30 * time.Second

// DefaultMaxBytesPerObject is the size threshold that triggers an
// upload for a single partition before the interval fires.
const DefaultMaxBytesPerObject = 16 * 1024 * 1024 // 16 MiB compressed

// DefaultMaxEventsPerObject is the per-partition row count that
// triggers an upload before the interval fires.
const DefaultMaxEventsPerObject = 50_000

// API is the subset of the AWS S3 client surface the writer uses.
// Defined as an interface so a test can inject a fake without
// spinning up MinIO.
type API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Config configures an S3 Writer.
type Config struct {
	// Bucket is the destination bucket. Required.
	Bucket string
	// Prefix is the per-deployment top-level key prefix
	// (e.g. "telemetry-archive"). Defaults to "telemetry".
	Prefix string
	// Class controls the S3 storage class for archive objects
	// (e.g. "STANDARD_IA", "GLACIER_IR"). Defaults to
	// "STANDARD_IA" which trades 5\xc3\x97 cheaper storage for a
	// per-GB retrieval fee — appropriate for the archive role
	// where reads are rare. Set to STANDARD if reads will be
	// frequent.
	StorageClass string
	// FlushInterval, MaxBytesPerObject, MaxEventsPerObject —
	// see the corresponding Default* constants.
	FlushInterval      time.Duration
	MaxBytesPerObject  int
	MaxEventsPerObject int
}

func (c *Config) fillDefaults() {
	if c.Prefix == "" {
		c.Prefix = "telemetry"
	}
	if c.StorageClass == "" {
		c.StorageClass = string(types.StorageClassStandardIa)
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.MaxBytesPerObject <= 0 {
		c.MaxBytesPerObject = DefaultMaxBytesPerObject
	}
	if c.MaxEventsPerObject <= 0 {
		c.MaxEventsPerObject = DefaultMaxEventsPerObject
	}
}

// Writer batches archive records per-partition and uploads them
// to S3 on a size or interval trigger.
type Writer struct {
	client API
	cfg    Config
	logger *slog.Logger

	mu          sync.Mutex
	partitions  map[partitionKey]*partition
	startOnce   sync.Once
	stopOnce    sync.Once
	cancel      context.CancelFunc
	done        chan struct{}
	flushSignal chan struct{}

	uploaded    uint64
	uploadBytes uint64
	uploadFails uint64
}

// partitionKey groups events that share a destination object.
type partitionKey struct {
	TenantID   uuid.UUID
	Hour       time.Time // truncated to hour, UTC
	EventClass string
}

// partition holds buffered events for one (tenant, hour, class)
// tuple before they are uploaded.
type partition struct {
	buf       bytes.Buffer
	gzw       *gzip.Writer
	rows      int
	createdAt time.Time
}

// archiveRecord is the on-wire line format. JSON-Lines so the
// archive is human-grep-able even without msgpack tooling. The
// `payload_b64` field is the raw envelope payload bytes base64-
// encoded — the operator-facing contract for replay.
type archiveRecord struct {
	SchemaVersion uint8      `json:"schema_version"`
	EventID       uuid.UUID  `json:"event_id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	DeviceID      uuid.UUID  `json:"device_id"`
	SiteID        *uuid.UUID `json:"site_id,omitempty"`
	Timestamp     time.Time  `json:"timestamp"`
	EventClass    string     `json:"event_class"`
	Platform      string     `json:"platform"`
	PayloadB64    string     `json:"payload_b64"`
	RawB64        string     `json:"raw_envelope_b64"`
}

// New constructs a Writer. The flusher goroutine is started
// eagerly so a producer can call Archive immediately.
func New(client API, cfg Config, logger *slog.Logger) (*Writer, error) {
	if client == nil {
		return nil, errors.New("s3: client is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("s3: bucket is required")
	}
	cfg.fillDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	w := &Writer{
		client:     client,
		cfg:        cfg,
		logger:     logger,
		partitions: make(map[partitionKey]*partition),
		done:       make(chan struct{}),
	}
	w.start()
	return w, nil
}

// NewWithAWSConfig is a convenience constructor that wraps an
// aws.Config into the S3 client used by the writer. Most callers
// use this; the New constructor is the lower-level seam for tests.
func NewWithAWSConfig(awsCfg aws.Config, cfg Config, logger *slog.Logger) (*Writer, error) {
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	return New(client, cfg, logger)
}

// Archive enqueues an envelope for upload. The buffered batch is
// flushed by the background goroutine on a size or interval
// trigger. See HotWriter doc on Writer.Write for the same
// "buffered means queued, not durable yet" caveat.
func (w *Writer) Archive(_ context.Context, env schema.Envelope, raw []byte) error {
	hour := env.Timestamp.UTC().Truncate(time.Hour)
	key := partitionKey{
		TenantID:   env.TenantID,
		Hour:       hour,
		EventClass: string(env.EventClass),
	}
	rec := archiveRecord{
		SchemaVersion: env.SchemaVersion,
		EventID:       env.EventID,
		TenantID:      env.TenantID,
		DeviceID:      env.DeviceID,
		SiteID:        env.SiteID,
		Timestamp:     env.Timestamp.UTC(),
		EventClass:    string(env.EventClass),
		Platform:      string(env.Platform),
		PayloadB64:    base64.StdEncoding.EncodeToString(env.Payload),
		RawB64:        base64.StdEncoding.EncodeToString(raw),
	}
	line, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("s3: marshal archive record: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	p, ok := w.partitions[key]
	if !ok {
		p = &partition{createdAt: time.Now().UTC()}
		p.gzw = gzip.NewWriter(&p.buf)
		w.partitions[key] = p
	}
	if _, err := p.gzw.Write(line); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("s3: gzip write: %w", err)
	}
	p.rows++
	full := p.rows >= w.cfg.MaxEventsPerObject || p.buf.Len() >= w.cfg.MaxBytesPerObject
	w.mu.Unlock()
	if full {
		w.signalFlush()
	}
	return nil
}

// Stop drains the partitions with one final flush and closes the
// background loop. Honours the passed context for the final
// flush; remaining partitions are dropped if the context expires.
func (w *Writer) Stop(ctx context.Context) error {
	var stopErr error
	w.stopOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
		<-w.done
		stopErr = w.flushAll(ctx)
	})
	return stopErr
}

// Stats returns a snapshot of writer counters.
type Stats struct {
	OpenPartitions int
	Uploaded       uint64
	UploadBytes    uint64
	UploadFails    uint64
}

// Stats returns a snapshot of writer counters.
func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Stats{
		OpenPartitions: len(w.partitions),
		Uploaded:       w.uploaded,
		UploadBytes:    w.uploadBytes,
		UploadFails:    w.uploadFails,
	}
}

// --- internals ---

func (w *Writer) start() {
	w.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(context.Background())
		w.cancel = cancel
		w.flushSignal = make(chan struct{}, 1)
		go w.loop(runCtx)
	})
}

func (w *Writer) signalFlush() {
	select {
	case w.flushSignal <- struct{}{}:
	default:
	}
}

func (w *Writer) loop(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.flushAll(ctx); err != nil {
				w.logger.Warn("s3: flush failed", slog.Any("error", err))
			}
		case <-w.flushSignal:
			if err := w.flushAll(ctx); err != nil {
				w.logger.Warn("s3: flush failed", slog.Any("error", err))
			}
		}
	}
}

// flushAll uploads every currently-open partition. Partitions are
// detached from the live map under the mutex and uploaded outside
// the lock so a slow PUT doesn't block in-flight Archives.
func (w *Writer) flushAll(ctx context.Context) error {
	w.mu.Lock()
	if len(w.partitions) == 0 {
		w.mu.Unlock()
		return nil
	}
	parts := w.partitions
	w.partitions = make(map[partitionKey]*partition, len(parts))
	w.mu.Unlock()

	var firstErr error
	for key, p := range parts {
		if err := w.uploadPartition(ctx, key, p); err != nil {
			w.logger.Warn("s3: upload partition failed",
				slog.String("tenant", key.TenantID.String()),
				slog.String("hour", key.Hour.Format(time.RFC3339)),
				slog.String("class", key.EventClass),
				slog.Any("error", err))
			w.mu.Lock()
			w.uploadFails++
			w.mu.Unlock()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	return firstErr
}

// uploadPartition closes the gzip stream and PUTs the resulting
// object to S3. Each upload uses a fresh UUID flush_id suffix so
// concurrent flushes of the same partition (split-brain after a
// network blip) never overwrite each other — the archive is
// append-only at the object-key level.
func (w *Writer) uploadPartition(ctx context.Context, key partitionKey, p *partition) error {
	if err := p.gzw.Close(); err != nil {
		return fmt.Errorf("s3: close gzip: %w", err)
	}
	if p.buf.Len() == 0 {
		return nil
	}
	flushID := uuid.New()
	objectKey := fmt.Sprintf(
		"%s/tenant=%s/date=%s/hour=%02d/class=%s/%s.jsonl.gz",
		w.cfg.Prefix,
		key.TenantID.String(),
		key.Hour.Format("2006-01-02"),
		key.Hour.Hour(),
		key.EventClass,
		flushID.String(),
	)
	in := &s3.PutObjectInput{
		Bucket:          aws.String(w.cfg.Bucket),
		Key:             aws.String(objectKey),
		Body:            bytes.NewReader(p.buf.Bytes()),
		ContentEncoding: aws.String("gzip"),
		ContentType:     aws.String("application/x-ndjson"),
		StorageClass:    types.StorageClass(w.cfg.StorageClass),
		Metadata: map[string]string{
			"sng-rows":        fmt.Sprintf("%d", p.rows),
			"sng-tenant-id":   key.TenantID.String(),
			"sng-event-class": key.EventClass,
		},
	}
	if _, err := w.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("s3: put object %s: %w", objectKey, err)
	}
	w.mu.Lock()
	w.uploaded++
	w.uploadBytes += uint64(p.buf.Len())
	w.mu.Unlock()
	return nil
}
