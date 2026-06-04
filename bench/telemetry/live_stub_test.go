//go:build !integration

package main

import (
	"errors"
	"testing"
)

// In the default (no-tag) build the container-backed runners are stubs
// that must refuse cleanly rather than panic or silently no-op. The
// real runners are exercised by live_integration_test.go under
// `-tags=integration`.
func TestLiveRunnersRequireIntegrationTag(t *testing.T) {
	for _, runner := range []func(Options) (*Report, error){
		liveIngestRate, liveCHWriteRate, liveS3Archive, liveFullPipeline,
	} {
		if _, err := runner(Options{}); !errors.Is(err, errIntegrationRequired) {
			t.Errorf("expected errIntegrationRequired, got %v", err)
		}
	}
}
