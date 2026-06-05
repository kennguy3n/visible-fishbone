package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

// reSquashName matches golang-migrate migration filenames in either
// direction: <version>_<name>.up.sql / <version>_<name>.down.sql.
var reSquashName = regexp.MustCompile(`^(\d+)_([A-Za-z0-9_]+)\.(up|down)\.sql$`)

// squashFile is one parsed migration file (a single direction).
type squashFile struct {
	version uint
	file    string // full filename, e.g. 007_app_registry.up.sql
	label   string // the <name> segment, e.g. app_registry
	sql     string
}

// runSquash generates a single consolidated baseline migration from
// the embedded migration set. It needs no database connection: it
// reads the embedded SQL, concatenates every `up` in ascending
// version order (and every `down` in descending order) into one
// baseline pair, and writes them to an output directory.
//
// The baseline is for NEW deployments only: a fresh database applies
// the single baseline pair instead of replaying 001..NNN
// one-by-one, and records schema version = NNN so subsequent
// migrations (NNN+1 …) apply on top unchanged. EXISTING deployments
// keep applying the individual files and must never be pointed at
// the baseline. See docs/migration-consolidation.md.
func runSquash(stdout, stderr *os.File, args []string) error {
	fs := newSquashFlags(stderr)
	if err := fs.parse(args); err != nil {
		return err
	}

	ups, downs, maxVersion, err := collectSquashFiles(migrate.SourceFS())
	if err != nil {
		return err
	}
	if len(ups) == 0 {
		return fmt.Errorf("squash: no migrations found to consolidate")
	}

	upSQL := renderBaseline(ups, maxVersion, "up", false)
	downSQL := renderBaseline(downs, maxVersion, "down", true)

	base := fmt.Sprintf("%03d_consolidated_baseline", maxVersion)
	upPath := filepath.Join(fs.outDir, base+".up.sql")
	downPath := filepath.Join(fs.outDir, base+".down.sql")

	if err := ensureWritable(fs.outDir, []string{upPath, downPath}, fs.force); err != nil {
		return err
	}
	if err := os.WriteFile(upPath, []byte(upSQL), 0o600); err != nil {
		return fmt.Errorf("squash: write %s: %w", upPath, err)
	}
	if err := os.WriteFile(downPath, []byte(downSQL), 0o600); err != nil {
		return fmt.Errorf("squash: write %s: %w", downPath, err)
	}

	_, _ = fmt.Fprintf(stdout,
		"sng-migrate: squash ok — consolidated %d migration(s) (001..%03d) into:\n  %s\n  %s\n",
		len(ups), maxVersion, upPath, downPath)
	_, _ = fmt.Fprintf(stdout,
		"sng-migrate: fresh deployments apply this baseline and record schema version %d; "+
			"existing deployments keep the individual files (see docs/migration-consolidation.md)\n",
		maxVersion)
	return nil
}

// squashFlags holds parsed flags for `squash`.
type squashFlags struct {
	outDir string
	force  bool
	stderr *os.File
}

func newSquashFlags(stderr *os.File) *squashFlags {
	return &squashFlags{stderr: stderr, outDir: filepath.Join("migrations", "baseline")}
}

func (f *squashFlags) parse(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--force" || a == "-force":
			f.force = true
		case a == "--out" || a == "-out":
			if i+1 >= len(args) {
				return newUsageError("squash: --out requires a directory argument")
			}
			i++
			f.outDir = args[i]
		case strings.HasPrefix(a, "--out="):
			f.outDir = strings.TrimPrefix(a, "--out=")
		case strings.HasPrefix(a, "-out="):
			f.outDir = strings.TrimPrefix(a, "-out=")
		default:
			return newUsageError("squash: unexpected argument %q", a)
		}
	}
	if f.outDir == "" {
		return newUsageError("squash: --out directory must not be empty")
	}
	return nil
}

// collectSquashFiles reads every embedded migration, returning the up
// files sorted ascending, the down files sorted ascending (the caller
// reverses them for the baseline down), and the highest version seen.
// It errors if the same (version, direction) appears twice so a
// duplicate or mis-numbered file cannot silently drop SQL.
func collectSquashFiles(fsys fs.FS) (ups, downs []squashFile, maxVersion uint, err error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("squash: read embedded migrations: %w", err)
	}
	seenUp := map[uint]string{}
	seenDown := map[uint]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		mm := reSquashName.FindStringSubmatch(e.Name())
		if mm == nil {
			continue
		}
		v64, perr := strconv.ParseUint(mm[1], 10, 32)
		if perr != nil {
			return nil, nil, 0, fmt.Errorf("squash: parse version from %q: %w", e.Name(), perr)
		}
		v := uint(v64)
		b, rerr := fs.ReadFile(fsys, e.Name())
		if rerr != nil {
			return nil, nil, 0, fmt.Errorf("squash: read %q: %w", e.Name(), rerr)
		}
		sfile := squashFile{version: v, file: e.Name(), label: mm[2], sql: string(b)}
		if mm[3] == "up" {
			if prev, dup := seenUp[v]; dup {
				return nil, nil, 0, fmt.Errorf("squash: duplicate up version %d (%s and %s)", v, prev, e.Name())
			}
			seenUp[v] = e.Name()
			ups = append(ups, sfile)
		} else {
			if prev, dup := seenDown[v]; dup {
				return nil, nil, 0, fmt.Errorf("squash: duplicate down version %d (%s and %s)", v, prev, e.Name())
			}
			seenDown[v] = e.Name()
			downs = append(downs, sfile)
		}
		if v > maxVersion {
			maxVersion = v
		}
	}
	// Every up must have a matching down (and vice versa) so the
	// generated baseline is fully reversible.
	for v, name := range seenUp {
		if _, ok := seenDown[v]; !ok {
			return nil, nil, 0, fmt.Errorf("squash: %s has no matching .down.sql", name)
		}
	}
	for v, name := range seenDown {
		if _, ok := seenUp[v]; !ok {
			return nil, nil, 0, fmt.Errorf("squash: %s has no matching .up.sql", name)
		}
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].version < ups[j].version })
	sort.Slice(downs, func(i, j int) bool { return downs[i].version < downs[j].version })
	return ups, downs, maxVersion, nil
}

// renderBaseline concatenates files into one baseline SQL document.
// When reverse is true (the down direction) files are emitted in
// descending version order so the baseline tears the schema down in
// the inverse order it was built up.
func renderBaseline(files []squashFile, maxVersion uint, direction string, reverse bool) string {
	ordered := make([]squashFile, len(files))
	copy(ordered, files)
	if reverse {
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].version > ordered[j].version })
	} else {
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].version < ordered[j].version })
	}

	var b strings.Builder
	fmt.Fprintf(&b, "-- Code generated by `sng-migrate squash` on %s. DO NOT EDIT BY HAND.\n",
		time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "-- Consolidated %s baseline of migrations 001..%03d.\n", direction, maxVersion)
	b.WriteString("--\n")
	b.WriteString("-- This baseline is for NEW deployments only. A fresh database applies\n")
	b.WriteString("-- it once instead of replaying every individual migration; it must be\n")
	b.WriteString(fmt.Sprintf("-- recorded as schema version %d so that migration %03d and later apply\n", maxVersion, maxVersion+1))
	b.WriteString("-- on top unchanged. EXISTING deployments must keep applying the\n")
	b.WriteString("-- individual migration files and must NOT run this baseline.\n")
	b.WriteString("-- Regenerate with `sng-migrate squash`; see docs/migration-consolidation.md.\n\n")

	for _, f := range ordered {
		fmt.Fprintf(&b, "-- ===========================================================================\n")
		fmt.Fprintf(&b, "-- %s\n", f.file)
		fmt.Fprintf(&b, "-- ===========================================================================\n")
		body := strings.TrimRight(f.sql, "\n")
		b.WriteString(body)
		b.WriteString("\n\n")
	}
	return b.String()
}

// ensureWritable creates outDir if needed and, unless force is set,
// refuses to clobber existing baseline files.
func ensureWritable(outDir string, paths []string, force bool) error {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("squash: create output dir %s: %w", outDir, err)
	}
	if force {
		return nil
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return newUsageError("squash: %s already exists; pass --force to overwrite", p)
		}
	}
	return nil
}
