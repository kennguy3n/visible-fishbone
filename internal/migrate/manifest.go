package migrate

// manifest.go is the structural guard over the *set* of migration
// files, as opposed to validator.go which analyses the SQL *inside*
// one file. Its single job is to catch the merge-order collision
// that branch-isolated CI cannot: two feature branches that each
// pick the next free version number (e.g. both add a `055_*`) pass
// their own CI green, then break `main` the moment both merge —
// golang-migrate refuses a source with two files at the same
// version, and the embedded-FS round-trip tests fail with a cryptic
// "duplicate version" deep in a -race run.
//
// CheckVersionSequence turns that latent, post-merge failure into an
// explicit, fast, locally-runnable gate (`sng-migrate check-versions`)
// that names the colliding files directly. It is content-free: it
// only inspects filenames, so it needs no database and runs in
// milliseconds in the fast PR lint job.

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// migrationNameRe matches the canonical `NNN_name.(up|down).sql`
// migration filename: a three-digit zero-padded version, a
// lower-snake-case name, and an up/down direction. The same shape is
// asserted by TestSourceFS_Pairs; keeping it here lets the CLI and
// the test share one definition of "well-formed migration filename".
var migrationNameRe = regexp.MustCompile(`^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$`)

// SequenceError aggregates every structural problem found across the
// migration set: malformed filenames, duplicate version numbers,
// gaps in the sequence, and unpaired up/down files. It implements
// error so callers can return it directly; Problems is exported so a
// structured caller can inspect the individual breaches.
type SequenceError struct {
	Problems []string
}

func (e *SequenceError) Error() string {
	if len(e.Problems) == 0 {
		return "migration version check failed: no problems recorded"
	}
	lines := make([]string, 0, len(e.Problems)+1)
	lines = append(lines, fmt.Sprintf("migration version check failed: %d problem(s):", len(e.Problems)))
	for _, p := range e.Problems {
		lines = append(lines, "  "+p)
	}
	return strings.Join(lines, "\n")
}

// CheckVersionSequence verifies that the `.sql` migrations in fsys
// form a gap-free, duplicate-free sequence 001..N in which every
// version has exactly one `.up.sql` and one matching `.down.sql`.
//
// It returns a *SequenceError describing every problem it finds (it
// does not stop at the first), or nil when the set is well-formed. A
// read error on the directory is returned as a plain error.
//
// This is deliberately stricter than golang-migrate's own loader:
// migrate only rejects exact duplicate versions, whereas this also
// flags gaps (a skipped number usually means a file was lost in a
// rebase) and unpaired files (a missing down breaks rollback) — the
// other two filename mistakes that surface only at deploy time.
func CheckVersionSequence(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read migration dir: %w", err)
	}

	var problems []string
	// versionNames maps a version number to the distinct base names
	// seen at that version. More than one name at a version is the
	// collision we exist to catch.
	versionNames := map[int]map[string]struct{}{}
	// haveUp/haveDown track, per "NNN_name" key, which directions are
	// present so an unpaired file is reported.
	haveUp := map[string]struct{}{}
	haveDown := map[string]struct{}{}
	keyVersion := map[string]int{}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		m := migrationNameRe.FindStringSubmatch(name)
		if m == nil {
			problems = append(problems, fmt.Sprintf("file %q does not match NNN_name.(up|down).sql", name))
			continue
		}
		version, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			// Unreachable given the \d{3} match, but handled rather
			// than panicked so a future regex change fails loudly.
			problems = append(problems, fmt.Sprintf("file %q has an unparseable version %q", name, m[1]))
			continue
		}
		base := m[2]
		key := m[1] + "_" + base
		keyVersion[key] = version
		if versionNames[version] == nil {
			versionNames[version] = map[string]struct{}{}
		}
		versionNames[version][base] = struct{}{}
		switch m[3] {
		case "up":
			haveUp[key] = struct{}{}
		case "down":
			haveDown[key] = struct{}{}
		}
	}

	if len(versionNames) == 0 {
		problems = append(problems, "no migrations found")
		return &SequenceError{Problems: problems}
	}

	// Duplicate version numbers: more than one distinct name sharing
	// a version. Report the names so the author knows exactly which
	// two files to renumber.
	versions := make([]int, 0, len(versionNames))
	for v, names := range versionNames {
		versions = append(versions, v)
		if len(names) > 1 {
			sorted := make([]string, 0, len(names))
			for n := range names {
				sorted = append(sorted, fmt.Sprintf("%03d_%s", v, n))
			}
			sort.Strings(sorted)
			problems = append(problems, fmt.Sprintf("duplicate migration version %d: %s", v, strings.Join(sorted, ", ")))
		}
	}
	sort.Ints(versions)

	// Contiguity: the sorted version numbers must be exactly 1..N.
	// The first version must be 1, and each subsequent version must
	// be exactly one greater than its predecessor.
	if versions[0] != 1 {
		problems = append(problems, fmt.Sprintf("migration sequence must start at 001, but the lowest version is %03d", versions[0]))
	}
	for i := 1; i < len(versions); i++ {
		prev, cur := versions[i-1], versions[i]
		if cur == prev {
			continue // duplicate already reported above
		}
		if cur != prev+1 {
			problems = append(problems, fmt.Sprintf("gap in migration sequence: %03d follows %03d (expected %03d)", cur, prev, prev+1))
		}
	}

	// Pairing: every version+name key must have both an up and a
	// down file.
	keys := make([]string, 0, len(keyVersion))
	for k := range keyVersion {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, up := haveUp[k]
		_, down := haveDown[k]
		switch {
		case up && !down:
			problems = append(problems, fmt.Sprintf("migration %q has an up file but no matching down file", k))
		case down && !up:
			problems = append(problems, fmt.Sprintf("migration %q has a down file but no matching up file", k))
		}
	}

	if len(problems) > 0 {
		return &SequenceError{Problems: problems}
	}
	return nil
}
