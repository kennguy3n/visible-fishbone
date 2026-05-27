package migrate

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestSourceFS_Pairs is a static check that every up migration has
// a matching down migration with the same version+name prefix. A
// missing partner is the single most common migration mistake and
// is essentially free to catch at test time.
func TestSourceFS_Pairs(t *testing.T) {
	files, err := fs.ReadDir(SourceFS(), ".")
	if err != nil {
		t.Fatalf("read embedded FS: %v", err)
	}

	// Pattern: NNN_name.up.sql / NNN_name.down.sql
	re := regexp.MustCompile(`^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$`)

	ups := map[string]string{}
	downs := map[string]string{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		m := re.FindStringSubmatch(name)
		if m == nil {
			t.Errorf("migration file %q does not match NNN_name.(up|down).sql", name)
			continue
		}
		key := m[1] + "_" + m[2]
		switch m[3] {
		case "up":
			if other, dup := ups[key]; dup {
				t.Errorf("duplicate up migration for %q: %q and %q", key, other, name)
			}
			ups[key] = name
		case "down":
			if other, dup := downs[key]; dup {
				t.Errorf("duplicate down migration for %q: %q and %q", key, other, name)
			}
			downs[key] = name
		}
	}

	if len(ups) == 0 {
		t.Fatal("no up migrations found in embedded FS")
	}

	// Every up must have a down and vice-versa.
	for key, upName := range ups {
		if _, ok := downs[key]; !ok {
			t.Errorf("missing down migration for %q (up file %q)", key, upName)
		}
	}
	for key, downName := range downs {
		if _, ok := ups[key]; !ok {
			t.Errorf("missing up migration for %q (down file %q)", key, downName)
		}
	}

	// Versions must form a contiguous sequence starting at 001.
	versions := make([]string, 0, len(ups))
	for key := range ups {
		versions = append(versions, key[:3])
	}
	sort.Strings(versions)
	for i, v := range versions {
		want := pad3(i + 1)
		if v != want {
			t.Errorf("migration versions are not contiguous: expected %q at index %d, got %q", want, i, v)
		}
	}
}

func pad3(n int) string {
	switch {
	case n < 10:
		return "00" + itoa(n)
	case n < 100:
		return "0" + itoa(n)
	default:
		return itoa(n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestSourceFS_UpFileContent does a smoke check that the initial
// schema migration sets up RLS on the tenant-scoped tables with the
// SNG-namespaced GUC. A typo here silently breaks tenant isolation
// for the whole product, so the test is intentionally specific.
func TestSourceFS_UpFileContent(t *testing.T) {
	b, err := fs.ReadFile(SourceFS(), path.Clean("001_initial_schema.up.sql"))
	if err != nil {
		t.Fatalf("read 001 up: %v", err)
	}
	content := string(b)

	wantContain := []string{
		"current_setting('sng.tenant_id'",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TABLE tenants",
		"CREATE TABLE sites",
		"CREATE TABLE users",
		"CREATE TABLE roles",
		"CREATE TABLE user_roles",
		"CREATE TABLE devices",
		"CREATE TABLE claim_tokens",
		"CREATE TABLE audit_log",
		"CREATE TABLE policy_graphs",
		"CREATE TABLE policy_bundles",
		"'windows'", "'macos'", "'linux'", "'ios'", "'android'",
		"'edge'", "'endpoint'", "'cloud'", "'mobile'",
	}
	for _, s := range wantContain {
		if !strings.Contains(content, s) {
			t.Errorf("001 up missing expected substring %q", s)
		}
	}

	// Defensive: ensure we never write the sn360 GUC name in this
	// repo's migrations — that would cross-couple SNG and SN360
	// RLS policies on shared connections.
	if strings.Contains(content, "current_setting('sn360.tenant_id'") {
		t.Errorf("001 up references sn360.tenant_id GUC; should be sng.tenant_id")
	}
}

// TestNew_EmptyDSN exercises the explicit-error path that prevents
// callers from accidentally booting the runner against the empty
// string (which migrate's URL parser otherwise turns into a vague
// "scheme: " error).
func TestNew_EmptyDSN(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("expected error for empty DSN, got nil")
	}
}

// TestNew_BadScheme exercises that DSNs without the pgx5:// scheme
// are rejected by golang-migrate, surfaced as a wrapped error.
func TestNew_BadScheme(t *testing.T) {
	_, err := New("postgres://localhost/sng?sslmode=disable")
	if err == nil {
		t.Fatal("expected error for non-pgx5 scheme, got nil")
	}
}

// TestErrNoChange exposes the public alias so callers using
// errors.Is can match the canonical migrate sentinel.
func TestErrNoChange(t *testing.T) {
	if !errors.Is(ErrNoChange, ErrNoChange) {
		t.Fatal("errors.Is(ErrNoChange, ErrNoChange) should be true")
	}
}
