package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// measure.go holds the container-free, CPU-bound measurements that are
// genuinely measured even in --dry-run mode: msgpack encode throughput,
// average wire size, and the real gzip compression ratio of the S3
// archive line format. These ground the dry-run report in real numbers
// rather than fabricated throughput.

// EncodeStats is the result of measuring the msgpack encode path.
type EncodeStats struct {
	// Events is how many envelopes were encoded.
	Events int
	// Elapsed is the wall time spent encoding.
	Elapsed time.Duration
	// TotalWireBytes is the summed marshaled size.
	TotalWireBytes int64
}

// EventsPerSec is the single-core encode throughput. Returns 0 for a
// zero-duration measurement.
func (s EncodeStats) EventsPerSec() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	return float64(s.Events) / s.Elapsed.Seconds()
}

// AvgWireBytes is the mean marshaled envelope size.
func (s EncodeStats) AvgWireBytes() float64 {
	if s.Events == 0 {
		return 0
	}
	return float64(s.TotalWireBytes) / float64(s.Events)
}

// MeasureEncode marshals n envelopes from the generator and times the
// encode path. It returns the marshaled bytes of the final envelope so
// the caller can avoid the compiler optimising the loop away, but the
// headline outputs are in EncodeStats.
func MeasureEncode(g *Generator, n int) (EncodeStats, error) {
	stats := EncodeStats{Events: n}
	start := time.Now()
	var total int64
	for i := 0; i < n; i++ {
		env := g.Next()
		b, err := schema.Marshal(env)
		if err != nil {
			return EncodeStats{}, fmt.Errorf("marshal envelope %d: %w", i, err)
		}
		total += int64(len(b))
	}
	stats.Elapsed = time.Since(start)
	stats.TotalWireBytes = total
	return stats, nil
}

// archiveLine mirrors the JSON-Lines record the S3 archiver writes
// (internal/service/telemetry/s3.archiveRecord) so the measured
// compression ratio matches what the production archiver achieves.
type archiveLine struct {
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

// CompressionStats captures the result of gzip-compressing a batch of
// archive lines the way the S3 cold-path writer does.
type CompressionStats struct {
	// Events is the number of archive records compressed.
	Events int
	// Uncompressed is the pre-gzip JSON-Lines byte total.
	Uncompressed int64
	// Compressed is the post-gzip byte total.
	Compressed int64
}

// Ratio is uncompressed/compressed (>1 means gzip shrank the data).
func (s CompressionStats) Ratio() float64 {
	if s.Compressed == 0 {
		return 0
	}
	return float64(s.Uncompressed) / float64(s.Compressed)
}

// AvgCompressedBytesPerEvent is the mean post-gzip bytes per event.
func (s CompressionStats) AvgCompressedBytesPerEvent() float64 {
	if s.Events == 0 {
		return 0
	}
	return float64(s.Compressed) / float64(s.Events)
}

// MeasureArchiveCompression builds n archive lines from the generator,
// gzip-compresses them as one object (the archiver groups events into
// per-partition gzip streams), and reports the real compression ratio.
func MeasureArchiveCompression(g *Generator, n int) (CompressionStats, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	for i := 0; i < n; i++ {
		env := g.Next()
		wire, err := schema.Marshal(env)
		if err != nil {
			return CompressionStats{}, fmt.Errorf("marshal envelope %d: %w", i, err)
		}
		line := archiveLine{
			SchemaVersion: env.SchemaVersion,
			EventID:       env.EventID,
			TenantID:      env.TenantID,
			DeviceID:      env.DeviceID,
			SiteID:        env.SiteID,
			Timestamp:     env.Timestamp,
			EventClass:    string(env.EventClass),
			Platform:      string(env.Platform),
			PayloadB64:    base64.StdEncoding.EncodeToString(env.Payload),
			RawB64:        base64.StdEncoding.EncodeToString(wire),
		}
		if err := enc.Encode(&line); err != nil {
			return CompressionStats{}, fmt.Errorf("encode archive line %d: %w", i, err)
		}
	}
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(raw.Bytes()); err != nil {
		return CompressionStats{}, fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return CompressionStats{}, fmt.Errorf("gzip close: %w", err)
	}
	return CompressionStats{
		Events:       n,
		Uncompressed: int64(raw.Len()),
		Compressed:   int64(gz.Len()),
	}, nil
}
