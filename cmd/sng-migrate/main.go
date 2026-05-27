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
	fs.Usage = func() {
		// Errors from stderr writes are intentionally ignored — if
		// stderr is broken the process is already in trouble.
		_, _ = fmt.Fprintf(stderr, "Usage: sng-migrate [--dsn URL] <command> [args]\n\n")
		_, _ = fmt.Fprintf(stderr, "Commands:\n")
		_, _ = fmt.Fprintf(stderr, "  up               apply every pending migration\n")
		_, _ = fmt.Fprintf(stderr, "  down [N]         roll back N steps (default 1)\n")
		_, _ = fmt.Fprintf(stderr, "  status           print current schema version + dirty flag\n")
		_, _ = fmt.Fprintf(stderr, "  version          alias of status\n")
		_, _ = fmt.Fprintf(stderr, "  force <V>        forcibly set version (recovery only)\n")
	}
	if err := fs.Parse(args); err != nil {
		return newUsageError("parse flags: %v", err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return newUsageError("missing command")
	}

	dsn := *dsnFlag
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		dsn = cfg.Postgres.MigrationURL()
	}

	r, err := migrate.New(dsn)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	switch rest[0] {
	case "up":
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
