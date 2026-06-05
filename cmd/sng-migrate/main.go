// Command sng-migrate is a thin CLI wrapper around the embedded
// schema migrations (see internal/migrate). It exists so the
// repository does not require a separate `migrate` binary install
// — the SQL files travel inside the binary via `//go:embed`.
//
// Usage:
//
//	sng-migrate up                # apply all pending migrations
//	sng-migrate down [N]          # roll back N steps (default 1)
//	sng-migrate status            # print the current version
//	sng-migrate version           # alias of `status`
//	sng-migrate force <V>         # force-set version (recovery only)
//	sng-migrate validate [files]  # lint migration SQL for lock safety
//	sng-migrate squash            # generate a consolidated baseline migration
//
// Lock-safety flags (apply to `up`):
//
//	--lock-timeout DUR  bound each DDL statement's lock wait (default 5s)
//	--online            route through the OnlineMigrator: inject
//	                    lock_timeout into the connection and reject
//	                    pending migrations that violate the validator
//	--dry-run           print the DDL `up` would apply, then exit
//
// Configuration is read from the same `PG_*` environment variables
// as the main service (see `.env.example`).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

// exitCode lets `main` translate a structured error from `run` into
// a process exit code without scattering os.Exit calls through the
// codebase. Tests drive `run` directly and assert on the returned
// error.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var ue *usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "sng-migrate: %v\n", err)
			os.Exit(exitUsage)
		}
		fmt.Fprintf(os.Stderr, "sng-migrate: %v\n", err)
		os.Exit(exitError)
	}
	os.Exit(exitOK)
}

// usageError signals that the user invoked the CLI incorrectly
// (missing/invalid arguments). main() maps this to exitUsage so
// shell scripts can distinguish "you used me wrong" from "your DB
// rejected my migrations".
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func newUsageError(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("sng-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsnFlag := fs.String("dsn", os.Getenv("MIGRATIONS_DSN"), "explicit Postgres URL (defaults to PG_* env vars)")
	onlineFlag := fs.Bool("online", false, "route `up` through the OnlineMigrator (lock_timeout + validator gate)")
	dryRunFlag := fs.Bool("dry-run", false, "print the DDL `up` would apply, without applying it")
	lockTimeoutFlag := fs.Duration("lock-timeout", migrate.DefaultLockTimeout, "per-statement lock_timeout for `up` (used with --online)")
	fs.Usage = func() {
		// Errors from stderr writes are intentionally ignored — if
		// stderr is broken the process is already in trouble.
		_, _ = fmt.Fprintf(stderr, "Usage: sng-migrate [--dsn URL] [--online] [--dry-run] [--lock-timeout DUR] <command> [args]\n\n")
		_, _ = fmt.Fprintf(stderr, "Commands:\n")
		_, _ = fmt.Fprintf(stderr, "  up               apply every pending migration\n")
		_, _ = fmt.Fprintf(stderr, "  down [N]         roll back N steps (default 1)\n")
		_, _ = fmt.Fprintf(stderr, "  status           print current schema version + dirty flag\n")
		_, _ = fmt.Fprintf(stderr, "  version          alias of status\n")
		_, _ = fmt.Fprintf(stderr, "  force <V>        forcibly set version (recovery only)\n")
		_, _ = fmt.Fprintf(stderr, "  validate [files] lint migration SQL for lock safety (no DB needed)\n")
		_, _ = fmt.Fprintf(stderr, "  squash           generate a consolidated baseline migration (no DB needed)\n")
		_, _ = fmt.Fprintf(stderr, "                   flags: --out DIR (default migrations/baseline), --force\n")
	}
	if err := fs.Parse(args); err != nil {
		return newUsageError("parse flags: %v", err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return newUsageError("missing command")
	}

	// `validate` is a static-analysis command: it needs no database
	// connection, so it is handled before any DSN resolution.
	if rest[0] == "validate" {
		return runValidate(stdout, stderr, rest[1:])
	}

	// `squash` only reads the embedded migration SQL and writes the
	// generated baseline to disk; like `validate` it needs no
	// database connection, so handle it before DSN resolution.
	if rest[0] == "squash" {
		return runSquash(stdout, stderr, rest[1:])
	}

	dsn := *dsnFlag
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		dsn = cfg.Postgres.MigrationURL()
	}

	// `--online up` builds its own Runner from a lock_timeout-augmented
	// DSN (see runOnlineUp), so creating the shared Runner below would
	// open a second connection that is never used. Short-circuit before
	// that. `--dry-run` keeps precedence over `--online` (it touches no
	// DB at all but still reads pending migrations through the shared
	// Runner), so it is excluded here.
	if rest[0] == "up" && *onlineFlag && !*dryRunFlag {
		return runOnlineUp(stdout, dsn, *lockTimeoutFlag)
	}

	r, err := migrate.New(dsn)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	switch rest[0] {
	case "up":
		if *dryRunFlag {
			if *onlineFlag {
				// --dry-run touches no DB, so it cannot exercise the
				// online wrapper; it just prints pending DDL. Warn so an
				// operator who passed both does not assume the online
				// path was simulated.
				_, _ = fmt.Fprintln(stderr, "sng-migrate: --dry-run takes precedence over --online; "+
					"printing pending migrations without the online wrapper")
			}
			return runDryRun(stdout, r)
		}
		if err := r.Up(); err != nil {
			return err
		}
		return printStatus(stdout, r, "up")
	case "down":
		steps := 1
		if len(rest) > 1 {
			n, err := strconv.Atoi(rest[1])
			if err != nil || n <= 0 {
				return newUsageError("down: expected positive integer step count, got %q", rest[1])
			}
			steps = n
		}
		if err := r.Down(steps); err != nil {
			return err
		}
		return printStatus(stdout, r, "down")
	case "status", "version":
		return printStatus(stdout, r, "status")
	case "force":
		if len(rest) < 2 {
			return newUsageError("force: missing version argument")
		}
		v, err := strconv.Atoi(rest[1])
		if err != nil || v < 0 {
			return newUsageError("force: expected non-negative integer, got %q", rest[1])
		}
		if err := r.Force(v); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "sng-migrate: forced version to %d\n", v); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	default:
		fs.Usage()
		return newUsageError("unknown command: %s", rest[0])
	}
}

// runValidate lints migration SQL for lock safety. With explicit
// file paths it validates exactly those (the CI use case: only the
// migrations a PR adds). With no arguments it validates every
// embedded migration except the grandfathered baseline, so the
// command is also useful as a local pre-flight.
func runValidate(stdout, stderr *os.File, files []string) error {
	mv := migrate.NewMigrationValidator(migrate.DefaultBaseline())

	if len(files) == 0 {
		// No paths given: validate every embedded migration. The frozen
		// baseline shields pre-existing files, so this stays green until
		// a NEW migration is added that is not on the baseline.
		all, err := migrate.BaselineFromFS(migrate.SourceFS())
		if err != nil {
			return fmt.Errorf("list embedded migrations: %w", err)
		}
		if err := mv.ValidateFiles(migrate.SourceFS(), all); err != nil {
			_, _ = fmt.Fprintln(stderr, err.Error())
			return err
		}
		_, _ = fmt.Fprintln(stdout, "sng-migrate: validate ok — no lock-safety violations")
		return nil
	}

	// Explicit paths are validated from the OS filesystem.
	if err := mv.ValidateFiles(os.DirFS("."), files); err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return err
	}
	_, _ = fmt.Fprintf(stdout, "sng-migrate: validate ok — %d file(s) clean\n", len(files))
	return nil
}

// runDryRun prints the SQL that an `up` would apply, derived from the
// current schema version and the embedded migrations, without
// touching the database beyond reading its version.
func runDryRun(stdout *os.File, r *migrate.Runner) error {
	v, _, err := r.Status()
	if err != nil {
		return err
	}
	pending, err := migrate.PendingUp(v)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		_, _ = fmt.Fprintf(stdout, "sng-migrate: dry-run — no pending migrations (version=%d)\n", v)
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "sng-migrate: dry-run — %d pending migration(s) from version %d:\n", len(pending), v)
	for _, p := range pending {
		_, _ = fmt.Fprintf(stdout, "\n-- %s (version %d)\n%s\n", p.Name, p.Version, p.UpSQL)
	}
	return nil
}

// runOnlineUp applies pending migrations through the OnlineMigrator
// path: it gates on the validator (refusing lock-unsafe new
// migrations) and injects lock_timeout into the connection so every
// DDL statement the runner executes is bounded — a stuck migration
// can no longer pin ACCESS EXCLUSIVE indefinitely.
func runOnlineUp(stdout *os.File, dsn string, lockTimeout time.Duration) error {
	// Gate: validate every embedded migration; the frozen baseline
	// grandfathers pre-existing files, so only NEW unsafe migrations
	// trip this.
	all, err := migrate.BaselineFromFS(migrate.SourceFS())
	if err != nil {
		return fmt.Errorf("list embedded migrations: %w", err)
	}
	if err := migrate.NewMigrationValidator(migrate.DefaultBaseline()).ValidateFiles(migrate.SourceFS(), all); err != nil {
		return err
	}

	timeoutDSN, err := migrate.WithLockTimeout(dsn, lockTimeout)
	if err != nil {
		return err
	}
	r, err := migrate.New(timeoutDSN)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	if err := r.Up(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "sng-migrate: online up ok — lock_timeout=%s\n", lockTimeout)
	return printStatus(stdout, r, "up")
}

func printStatus(out *os.File, r *migrate.Runner, op string) error {
	v, dirty, err := r.Status()
	if err != nil {
		return err
	}
	dirtyTag := ""
	if dirty {
		dirtyTag = " (dirty)"
	}
	if _, err := fmt.Fprintf(out, "sng-migrate: %s ok — version=%d%s\n", op, v, dirtyTag); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}
