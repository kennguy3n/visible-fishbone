package migrate

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// up/down are tiny helpers to build a MapFS migration pair with
// arbitrary (irrelevant) SQL bodies — CheckVersionSequence is
// content-free, so the body never matters.
func migFS(names ...string) fstest.MapFS {
	m := fstest.MapFS{}
	for _, n := range names {
		m[n] = &fstest.MapFile{Data: []byte("-- " + n + "\nSELECT 1;\n")}
	}
	return m
}

func TestCheckVersionSequence_OK(t *testing.T) {
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"002_b.up.sql", "002_b.down.sql",
		"003_c.up.sql", "003_c.down.sql",
	)
	if err := CheckVersionSequence(fsys); err != nil {
		t.Fatalf("expected well-formed sequence to pass, got: %v", err)
	}
}

func TestCheckVersionSequence_DuplicateVersion(t *testing.T) {
	// The exact collision this guard exists for: two different names
	// at the same version, as happens when two branches each add the
	// next free number.
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"002_b.up.sql", "002_b.down.sql",
		"002_c.up.sql", "002_c.down.sql",
	)
	err := CheckVersionSequence(fsys)
	if err == nil {
		t.Fatal("expected duplicate version to fail, got nil")
	}
	var se *SequenceError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SequenceError, got %T", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "duplicate migration version 2") {
		t.Errorf("error should name the duplicate version, got: %s", msg)
	}
	// Both colliding files must be named so the author knows what to
	// renumber.
	if !strings.Contains(msg, "002_b") || !strings.Contains(msg, "002_c") {
		t.Errorf("error should name both colliding files, got: %s", msg)
	}
}

func TestCheckVersionSequence_Gap(t *testing.T) {
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"003_c.up.sql", "003_c.down.sql",
	)
	err := CheckVersionSequence(fsys)
	if err == nil {
		t.Fatal("expected gap to fail, got nil")
	}
	if !strings.Contains(err.Error(), "gap in migration sequence") {
		t.Errorf("error should report the gap, got: %s", err.Error())
	}
}

func TestCheckVersionSequence_DoesNotStartAtOne(t *testing.T) {
	fsys := migFS(
		"002_b.up.sql", "002_b.down.sql",
		"003_c.up.sql", "003_c.down.sql",
	)
	err := CheckVersionSequence(fsys)
	if err == nil {
		t.Fatal("expected non-001 start to fail, got nil")
	}
	if !strings.Contains(err.Error(), "must start at 001") {
		t.Errorf("error should report the bad start, got: %s", err.Error())
	}
}

func TestCheckVersionSequence_MissingDown(t *testing.T) {
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"002_b.up.sql", // no down
	)
	err := CheckVersionSequence(fsys)
	if err == nil {
		t.Fatal("expected missing down to fail, got nil")
	}
	if !strings.Contains(err.Error(), "no matching down file") {
		t.Errorf("error should report the missing down, got: %s", err.Error())
	}
}

func TestCheckVersionSequence_MalformedName(t *testing.T) {
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"two_b.up.sql", "two_b.down.sql", // non-numeric version
	)
	err := CheckVersionSequence(fsys)
	if err == nil {
		t.Fatal("expected malformed name to fail, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should report the malformed name, got: %s", err.Error())
	}
}

func TestCheckVersionSequence_IgnoresNonSQLAndDirs(t *testing.T) {
	fsys := migFS(
		"001_a.up.sql", "001_a.down.sql",
		"002_b.up.sql", "002_b.down.sql",
		"README.md",
		"embed.go",
	)
	if err := CheckVersionSequence(fsys); err != nil {
		t.Fatalf("non-.sql files should be ignored, got: %v", err)
	}
}

// TestCheckVersionSequence_EmbeddedSource is the real guard: the
// migrations actually shipped in the binary must always form a
// clean sequence. This is the test that goes red the instant two
// branches collide on a version number after both merge to main.
func TestCheckVersionSequence_EmbeddedSource(t *testing.T) {
	if err := CheckVersionSequence(SourceFS()); err != nil {
		t.Fatalf("embedded migrations are not a clean version sequence: %v", err)
	}
}
