//go:build integration

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
)

// s3_archive_live.go is the MinIO (S3-compatible) measurement for the
// `s3-archive-rate` subcommand: it drives the production S3 Writer's
// gzip JSON-Lines cold path against a real object store and reports the
// archive throughput, object sizes, and end-to-end compression ratio.

// s3LiveEvents bounds events archived so the container run stays inside
// the test timeout. Throughput is a rate, so the cap is representative.
const s3LiveEvents = 50_000

// s3LiveMaxEventsPerObject is intentionally smaller than the production
// default so the bench produces several objects (exercising the
// roll-over path) rather than one giant object per partition.
const s3LiveMaxEventsPerObject = 10_000

func liveS3Archive(opts Options) (*Report, error) {
	ctx := context.Background()
	client, cleanup, err := startMinIO(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	const bucket = "sng-telemetry-bench"
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return nil, fmt.Errorf("create bucket: %w", err)
	}

	w, err := s3.New(client, s3.Config{
		Bucket:             bucket,
		Prefix:             "telemetry-archive",
		StorageClass:       "STANDARD", // MinIO rejects STANDARD_IA; prod uses IA
		MaxEventsPerObject: s3LiveMaxEventsPerObject,
		FlushInterval:      time.Second,
	}, quietLogger())
	if err != nil {
		return nil, fmt.Errorf("new s3 writer: %w", err)
	}

	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed})
	var rawTotal uint64
	start := time.Now()
	for i := 0; i < s3LiveEvents; i++ {
		env := g.Next()
		raw, err := schema.Marshal(env)
		if err != nil {
			_ = w.Stop(ctx)
			return nil, fmt.Errorf("marshal: %w", err)
		}
		rawTotal += uint64(len(raw))
		if err := w.Archive(ctx, env, raw); err != nil {
			_ = w.Stop(ctx)
			return nil, fmt.Errorf("archive: %w", err)
		}
	}
	if err := w.Stop(ctx); err != nil {
		return nil, fmt.Errorf("stop/flush: %w", err)
	}
	elapsed := time.Since(start)
	st := w.Stats()

	var throughput, avgObjBytes, compBytesPerEvent, ratio float64
	if elapsed > 0 {
		throughput = float64(s3LiveEvents) / elapsed.Seconds()
	}
	if st.Uploaded > 0 {
		avgObjBytes = float64(st.UploadBytes) / float64(st.Uploaded)
	}
	compBytesPerEvent = float64(st.UploadBytes) / float64(s3LiveEvents)
	if st.UploadBytes > 0 {
		ratio = float64(rawTotal) / float64(st.UploadBytes)
	}

	r := NewReport("s3-archive-rate", nowUnix(), opts.GitSHA, false)
	r.AddSection(Section{
		Title:   "Cold-path S3 archive (MinIO)",
		Summary: fmt.Sprintf("%s events archived as gzip JSON-Lines across %d object(s).", humanizeFloat(float64(s3LiveEvents)), st.Uploaded),
		Metrics: []MetricRow{
			{Name: "archive throughput", Unit: "events/sec", Actual: throughput, Verdict: VerdictInfo},
			{Name: "objects uploaded", Unit: "", Actual: float64(st.Uploaded), Verdict: VerdictInfo},
			{Name: "avg object size", Unit: "B", Actual: avgObjBytes, Verdict: VerdictInfo},
			{Name: "compressed size", Unit: "B/event", Actual: compBytesPerEvent, Verdict: VerdictInfo},
			{Name: "compression ratio", Unit: "x", Actual: ratio, Verdict: VerdictInfo, Note: "raw msgpack payload bytes vs. gzipped object bytes"},
			{Name: "upload failures", Unit: "", Actual: float64(st.UploadFails), Verdict: VerdictInfo},
		},
	})
	r.AddCaveat("Throughput reflects MinIO on the local Docker network, not S3 over the public internet; treat it as a pipeline-side ceiling, not an S3 SLA.")
	r.AddCaveat("Objects use the STANDARD storage class because MinIO rejects STANDARD_IA; production archives to STANDARD_IA (which the cost model prices).")
	r.AddCaveat("Compression ratio compares raw msgpack payload bytes against the gzipped object bytes (which also carry base64 + JSON-Lines framing), so it is an end-to-end archive ratio, not a pure gzip ratio.")
	return r, nil
}
