package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"001_a.up.sql":   {Data: []byte("CREATE TABLE a();")},
		"001_a.down.sql": {Data: []byte("DROP TABLE a;")},
		"002_b.up.sql":   {Data: []byte("CREATE TABLE b();")},
		"002_b.down.sql": {Data: []byte("DROP TABLE b;")},
		"010_c.up.sql":   {Data: []byte("CREATE TABLE c();")},
		"010_c.down.sql": {Data: []byte("DROP TABLE c;")},
	}
}

func TestCollectSquashFiles_OrdersAndMaxVersion(t *testing.T) {
	ups, downs, maxV, err := collectSquashFiles(testFS())
	if err != nil {
		t.Fatalf("collectSquashFiles: %v", err)
	}
	if maxV != 10 {
		t.Errorf("maxVersion = %d, want 10", maxV)
	}
	if len(ups) != 3 || len(downs) != 3 {
		t.Fatalf("got %d ups / %d downs, want 3 each", len(ups), len(downs))
	}
	wantOrder := []uint{1, 2, 10}
	for i, v := range wantOrder {
		if ups[i].version != v {
			t.Errorf("ups[%d].version = %d, want %d", i, ups[i].version, v)
		}
	}
}

func TestCollectSquashFiles_DuplicateVersion(t *testing.T) {
	fsys := testFS()
	fsys["002_dup.up.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	if _, _, _, err := collectSquashFiles(fsys); err == nil ||
		!strings.Contains(err.Error(), "duplicate up version 2") {
		t.Fatalf("expected duplicate-version error, got %v", err)
	}
}

func TestCollectSquashFiles_MissingDown(t *testing.T) {
	fsys := testFS()
	delete(fsys, "002_b.down.sql")
	if _, _, _, err := collectSquashFiles(fsys); err == nil ||
		!strings.Contains(err.Error(), "no matching .down.sql") {
		t.Fatalf("expected missing-down error, got %v", err)
	}
}

// TestCollectSquashFiles_RejectsUnrecognizedSQL guards the
// "never silently drop SQL" invariant: a .sql file whose name does not
// match the migration pattern (here a hyphen, which the loader regex
// also rejects) must fail loudly rather than be skipped, since a skip
// would yield a baseline that silently omits the file.
func TestCollectSquashFiles_RejectsUnrecognizedSQL(t *testing.T) {
	fsys := testFS()
	fsys["011_with-hyphen.up.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	fsys["011_with-hyphen.down.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	if _, _, _, err := collectSquashFiles(fsys); err == nil ||
		!strings.Contains(err.Error(), "unrecognized migration filename") {
		t.Fatalf("expected unrecognized-filename error, got %v", err)
	}
}

// TestCollectSquashFiles_SkipsNonSQL confirms a non-.sql entry is not
// treated as a malformed migration.
func TestCollectSquashFiles_SkipsNonSQL(t *testing.T) {
	fsys := testFS()
	fsys["README.md"] = &fstest.MapFile{Data: []byte("# not a migration")}
	if _, _, maxV, err := collectSquashFiles(fsys); err != nil || maxV != 10 {
		t.Fatalf("non-sql entry should be skipped; got maxV=%d err=%v", maxV, err)
	}
}

func TestRenderBaseline_UpAscending_DownDescending(t *testing.T) {
	ups, downs, maxV, err := collectSquashFiles(testFS())
	if err != nil {
		t.Fatal(err)
	}
	up := renderBaseline(ups, maxV, "up", false)
	if idxA, idxC := strings.Index(up, "001_a.up.sql"), strings.Index(up, "010_c.up.sql"); idxA == -1 || idxA > idxC {
		t.Errorf("up baseline not in ascending order (a=%d c=%d)", idxA, idxC)
	}
	down := renderBaseline(downs, maxV, "down", true)
	if idxC, idxA := strings.Index(down, "010_c.down.sql"), strings.Index(down, "001_a.down.sql"); idxC == -1 || idxC > idxA {
		t.Errorf("down baseline not in descending order (c=%d a=%d)", idxC, idxA)
	}
	if !strings.Contains(up, "DO NOT EDIT BY HAND") {
		t.Error("baseline missing generated-file header")
	}
}

func TestSquashFlags_Parse(t *testing.T) {
	f := newSquashFlags(os.Stderr)
	if err := f.parse([]string{"--out", "x/y", "--force"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.outDir != "x/y" || !f.force {
		t.Errorf("parsed flags wrong: outDir=%q force=%v", f.outDir, f.force)
	}
	if err := newSquashFlags(os.Stderr).parse([]string{"bogus"}); err == nil {
		t.Error("expected error for unexpected positional argument")
	}
}

func TestRunSquash_WritesAndRefusesClobber(t *testing.T) {
	dir := t.TempDir()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	if err := runSquash(devnull, devnull, []string{"--out", dir}); err != nil {
		t.Fatalf("runSquash: %v", err)
	}
	// The baseline version tracks the real embedded migration set.
	_, _, maxV, err := collectSquashFiles(migrate.SourceFS())
	if err != nil {
		t.Fatal(err)
	}
	upGlob, _ := filepath.Glob(filepath.Join(dir, "*_consolidated_baseline.up.sql"))
	downGlob, _ := filepath.Glob(filepath.Join(dir, "*_consolidated_baseline.down.sql"))
	if len(upGlob) != 1 || len(downGlob) != 1 {
		t.Fatalf("expected one up+down baseline, got up=%v down=%v", upGlob, downGlob)
	}
	if maxV == 0 {
		t.Fatal("expected a non-zero baseline version from embedded migrations")
	}

	// Re-running without --force must refuse to clobber.
	if err := runSquash(devnull, devnull, []string{"--out", dir}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected clobber refusal, got %v", err)
	}
	// With --force it overwrites.
	if err := runSquash(devnull, devnull, []string{"--out", dir, "--force"}); err != nil {
		t.Fatalf("runSquash --force: %v", err)
	}
}
