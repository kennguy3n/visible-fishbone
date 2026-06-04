package main

import (
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
)

// s3_archive.go owns the `s3-archive-rate` subcommand: how large the
// gzip-compressed cold-path archive objects are and what compression
// ratio the realistic JSON-Lines payloads achieve.
//
// Compression is pure CPU work, so the ratio and per-event sizes are
// genuinely measured even in --dry-run. The live measurement (uploading
// to a MinIO testcontainer through the production s3.Writer) lives in
// s3_archive_live.go behind `//go:build integration` and adds the real
// upload throughput and per-object byte sizes.

func runS3ArchiveRate(opts Options) (*Report, error) {
	if !opts.DryRun {
		return liveS3Archive(opts)
	}
	return dryRunS3Archive(opts)
}

func dryRunS3Archive(opts Options) (*Report, error) {
	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed})
	comp, err := MeasureArchiveCompression(g, opts.Samples)
	if err != nil {
		return nil, fmt.Errorf("measure compression: %w", err)
	}

	r := NewReport("s3-archive-rate", nowUnix(), opts.GitSHA, opts.DryRun)
	r.AddSection(Section{
		Title:   "S3 cold-path archive compression",
		Summary: fmt.Sprintf("gzip JSON-Lines (the archiver's wire format) over %d events; object roll-over at %d events / %d MiB.", comp.Events, s3.DefaultMaxEventsPerObject, s3.DefaultMaxBytesPerObject/(1024*1024)),
		Metrics: []MetricRow{
			{Name: "compression ratio", Unit: "x", Actual: comp.Ratio(), Verdict: VerdictInfo, Note: "uncompressed JSONL / gzip; measured on realistic payloads"},
			{Name: "compressed size", Unit: "B/event", Actual: comp.AvgCompressedBytesPerEvent(), Verdict: VerdictInfo},
			{Name: "uncompressed total", Unit: "B", Actual: float64(comp.Uncompressed), Verdict: VerdictInfo},
			{Name: "compressed total", Unit: "B", Actual: float64(comp.Compressed), Verdict: VerdictInfo},
		},
	})
	r.AddCaveat("Compression ratio is measured on the archiver's exact JSON-Lines record format (msgpack payload + raw envelope, base64-encoded); base64 inflates the pre-gzip size, which gzip then largely recovers.")
	r.AddCaveat("Dry-run does not upload; build with -tags=integration to measure real PUT throughput and per-object sizes against a MinIO container.")
	return r, nil
}
