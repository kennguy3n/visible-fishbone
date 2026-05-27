// Package migrations exposes the embedded SQL migration files for
// the ShieldNet Gateway control plane.
//
// Keeping the embed declaration in the same directory as the .sql
// files lets `//go:embed` reference them with a simple glob,
// independent of where the consuming package lives in the tree.
// Consumers (cmd/sng-migrate, tests, future tooling) import this
// package and use `FS` as the source for golang-migrate/v4's iofs
// source driver.
package migrations

import "embed"

// FS contains every *.sql file in this directory at compile time.
// The migrations land directly at the root of the FS (not in a
// nested `migrations/` subdir) so `iofs.New(FS, ".")` works
// without further sub-FS gymnastics.
//
//go:embed *.sql
var FS embed.FS
