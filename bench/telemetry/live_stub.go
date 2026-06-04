//go:build !integration

package main

// live_stub.go provides the live-runner symbols for the default
// (no-tag) build. The real container-backed implementations live in the
// `//go:build integration` files; without that tag the runners return
// errIntegrationRequired so `--dry-run` is the only available path and
// the binary still builds and runs everywhere (CI's fast gate, a laptop
// without Docker).

func liveIngestRate(Options) (*Report, error) { return nil, errIntegrationRequired }

func liveCHWriteRate(Options) (*Report, error) { return nil, errIntegrationRequired }

func liveS3Archive(Options) (*Report, error) { return nil, errIntegrationRequired }

func liveFullPipeline(Options) (*Report, error) { return nil, errIntegrationRequired }
