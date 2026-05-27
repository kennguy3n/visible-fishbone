package handler

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenAPISpec_HandlerCopyMatchesContractCopy guards against silent
// drift between the canonical, source-of-truth API contract at
// `api/openapi.yaml` (consumed by humans, SDK generators, and any
// other tooling that walks `api/` as a convention) and the
// `internal/handler/openapi.yaml` copy that `internal/handler/openapi.go`
// `//go:embed`s into the running binary.
//
// We have to keep two on-disk copies because `//go:embed` refuses
// any path that escapes the embedding file's package directory
// (no `..`), so the handler cannot embed `../../api/openapi.yaml`
// directly, and `//go:embed` does not follow symlinks. Without
// this test, an operator updating the canonical `api/openapi.yaml`
// would silently leave the embedded copy stale: `/api/v1/openapi.yaml`
// keeps serving the old spec while any externally-generated SDK
// reflects the new one — an asymmetry that hides API contract
// changes for an entire release cycle.
//
// The fix when this test fails is mechanical: copy
// `api/openapi.yaml` over `internal/handler/openapi.yaml` (or vice
// versa, whichever direction reflects the intended change) so the
// two files are byte-identical, then re-run the suite.
func TestOpenAPISpec_HandlerCopyMatchesContractCopy(t *testing.T) {
	t.Parallel()

	// Locate api/openapi.yaml relative to this test file's
	// directory. runtime.Caller(0) returns the source file path
	// recorded at compile time, which `go test` preserves even
	// when the binary is executed from a different cwd (e.g. via
	// `go test ./...` from the repo root vs. `go test .` from
	// inside the package).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate test source")
	}
	// internal/handler/openapi_sync_test.go -> repo root is two
	// directories up.
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	contractPath := filepath.Join(repoRoot, "api", "openapi.yaml")
	embedPath := filepath.Join(filepath.Dir(thisFile), "openapi.yaml")

	contract, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read canonical contract %s: %v", contractPath, err)
	}
	embed, err := os.ReadFile(embedPath)
	if err != nil {
		t.Fatalf("read embedded copy %s: %v", embedPath, err)
	}
	if string(contract) != string(embed) {
		t.Fatalf(
			"api/openapi.yaml (%d bytes) and internal/handler/openapi.yaml (%d bytes) have drifted.\n"+
				"Fix: copy the intended version over the other so the two files are byte-identical, e.g.:\n"+
				"\tcp api/openapi.yaml internal/handler/openapi.yaml",
			len(contract), len(embed))
	}
}
