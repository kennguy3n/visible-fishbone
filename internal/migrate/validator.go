package migrate

// validator.go implements static analysis of `.up.sql` migration
// files. The goal is to reject DDL patterns that take heavyweight
// locks (ACCESS EXCLUSIVE) for the duration of a table rewrite,
// which at 5,000 tenants turns a routine migration into a global
// outage. The rules mirror the lock-safe patterns the
// OnlineMigrator implements:
//
//   - ALTER TABLE ... ADD COLUMN ... NOT NULL without DEFAULT
//   - CREATE INDEX without CONCURRENTLY
//   - ALTER TABLE ... ALTER COLUMN ... TYPE (table rewrite)
//   - LOCK TABLE
//   - raw DROP COLUMN (no deprecation period)
//
// The analysis is deliberately conservative: it tokenises the SQL
// just enough to ignore comments, string literals, and dollar-
// quoted bodies (so a keyword inside a function body or a comment
// never trips a rule), then matches the surviving statements with
// anchored regexes. It is NOT a full SQL parser and does not try to
// be — a false positive is cheap to suppress with a baseline entry,
// whereas a false negative is a production outage.

import (
	_ "embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// baselineFile is the frozen list of migrations that pre-date the
// validator. It is embedded (not read from the migrations directory
// at runtime) precisely so it stays frozen: a new migration added to
// migrations/ does NOT appear here and is therefore validated, while
// the pre-existing files remain grandfathered.
//
//go:embed lint_baseline.txt
var baselineFile string

// DefaultBaseline parses the embedded frozen baseline into a slice
// of file base names, skipping blank lines and # comments.
func DefaultBaseline() []string {
	var out []string
	for _, line := range strings.Split(baselineFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// Rule identifies a single lock-safety rule. Stable string values
// are part of the CI contract: an operator reading a CI failure
// greps for these.
type Rule string

const (
	// RuleAddColumnNotNullNoDefault flags `ADD COLUMN ... NOT NULL`
	// without a DEFAULT. On a non-empty table Postgres must rewrite
	// every row to populate the column, holding ACCESS EXCLUSIVE for
	// the duration. Adding a DEFAULT lets Postgres 11+ record the
	// default in the catalog and skip the rewrite.
	RuleAddColumnNotNullNoDefault Rule = "add-column-not-null-no-default"
	// RuleIndexNotConcurrent flags `CREATE INDEX` without
	// CONCURRENTLY. A plain CREATE INDEX takes a SHARE lock that
	// blocks all writes to the table until the index is built.
	RuleIndexNotConcurrent Rule = "create-index-not-concurrent"
	// RuleAlterColumnType flags `ALTER COLUMN ... TYPE`. Changing a
	// column type rewrites the table under ACCESS EXCLUSIVE; the
	// online path is a shadow table + backfill (see OnlineMigrator).
	RuleAlterColumnType Rule = "alter-column-type"
	// RuleLockTable flags an explicit `LOCK TABLE`. There is no
	// lock-safe reason to take an explicit table lock inside a
	// migration.
	RuleLockTable Rule = "lock-table"
	// RuleDropColumn flags a raw `DROP COLUMN`. Dropping a column an
	// older application version still reads (or writes) breaks during
	// a rolling deploy; columns must go through a deprecation period
	// (stop reading -> stop writing -> drop) instead.
	RuleDropColumn Rule = "drop-column"
)

// Violation is a single rule breach located in a migration file.
type Violation struct {
	File    string
	Line    int
	Rule    Rule
	Message string
}

// String renders a violation in a `file:line: [rule] message` shape
// that mirrors the output of go vet and golangci-lint, so it slots
// into CI log scanning without special handling.
func (v Violation) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", v.File, v.Line, v.Rule, v.Message)
}

// ValidationError aggregates every violation found across a
// validation run. It implements error so callers can return it
// directly; Violations is exported so structured callers (a future
// JSON reporter, say) can inspect the individual breaches.
type ValidationError struct {
	Violations []Violation
}

func (e *ValidationError) Error() string {
	if len(e.Violations) == 0 {
		return "migration validation failed: no violations recorded"
	}
	lines := make([]string, 0, len(e.Violations)+1)
	lines = append(lines, fmt.Sprintf("migration validation failed: %d violation(s):", len(e.Violations)))
	for _, v := range e.Violations {
		lines = append(lines, "  "+v.String())
	}
	return strings.Join(lines, "\n")
}

// MigrationValidator performs the static analysis. The zero value is
// usable and enables every rule with an empty baseline; use
// NewMigrationValidator to set a baseline of grandfathered files.
type MigrationValidator struct {
	// baseline is the set of file base names (e.g.
	// "001_initial_schema.up.sql") that pre-date the validator and
	// are exempt from analysis. Existing migrations are not rewritten
	// (that would be a far riskier change than the outage the
	// validator prevents), so they are grandfathered here.
	baseline map[string]struct{}
}

// NewMigrationValidator returns a validator that skips any file
// whose base name is in baseline.
func NewMigrationValidator(baseline []string) *MigrationValidator {
	set := make(map[string]struct{}, len(baseline))
	for _, b := range baseline {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		set[b] = struct{}{}
	}
	return &MigrationValidator{baseline: set}
}

// IsBaselined reports whether the given file (matched on its base
// name) is grandfathered and therefore skipped.
func (mv *MigrationValidator) IsBaselined(name string) bool {
	_, ok := mv.baseline[path.Base(name)]
	return ok
}

// ValidateFiles reads and validates each path, accumulating
// violations across all of them. A baselined file contributes no
// violations. Returns a *ValidationError when any violation is
// found, or a plain error if a file cannot be read.
func (mv *MigrationValidator) ValidateFiles(fsys fs.FS, names []string) error {
	var all []Violation
	for _, name := range names {
		if mv.IsBaselined(name) {
			continue
		}
		// Only `.up.sql` files are analysed: down migrations roll
		// state back and are not the source of forward-migration
		// outages, and non-SQL paths are not migrations at all.
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read migration %q: %w", name, err)
		}
		all = append(all, mv.ValidateContent(path.Base(name), string(b))...)
	}
	if len(all) > 0 {
		return &ValidationError{Violations: all}
	}
	return nil
}

// ValidateContent analyses a single migration's SQL text and returns
// the violations it contains. file is used only to populate
// Violation.File. The baseline is not consulted here — callers that
// want baseline behaviour go through ValidateFiles.
//
// Statements are evaluated in source order so the analysis can track
// which tables this migration creates. An index on a table created
// earlier in the same migration is lock-safe regardless of
// CONCURRENTLY (the table is brand-new and empty, holds no rows to
// scan, and is invisible to other sessions until the migration
// commits), so it is exempt from the CONCURRENTLY rule — see
// newTables below.
func (mv *MigrationValidator) ValidateContent(file, sql string) []Violation {
	var out []Violation
	masked := maskSQL(sql)
	// newTables accumulates the (normalised) names of tables this
	// migration creates, so a later CREATE INDEX on one of them is
	// recognised as operating on a brand-new empty table.
	newTables := map[string]struct{}{}
	for _, st := range splitStatements(sql, masked) {
		if tbl, ok := createdTableName(st.norm); ok {
			newTables[tbl] = struct{}{}
		}
		out = append(out, checkStatement(file, st, newTables)...)
	}
	return out
}

// statement is one top-level SQL statement plus the 1-based line on
// which it starts. raw is the original text (for messages); norm is
// the masked text normalised to single-spaced upper case (for rule
// matching).
type statement struct {
	line int
	raw  string
	norm string
}

var wsRun = regexp.MustCompile(`\s+`)

// splitStatements walks the masked SQL, splitting on top-level
// semicolons. Because comments, string literals, and dollar-quoted
// bodies are blanked in the masked text (newlines preserved), every
// surviving semicolon is a real terminator and every surviving
// keyword is real code. Line numbers are computed against the
// original text so messages point at the author's file.
func splitStatements(orig, masked string) []statement {
	var stmts []statement
	start := 0
	flush := func(end int) {
		segMasked := masked[start:end]
		if strings.TrimSpace(segMasked) == "" {
			start = end + 1
			return
		}
		norm := strings.ToUpper(strings.TrimSpace(wsRun.ReplaceAllString(segMasked, " ")))
		// Locate the first non-space rune of the segment to compute
		// the starting line precisely.
		off := start
		for off < end && (masked[off] == ' ' || masked[off] == '\n' || masked[off] == '\t' || masked[off] == '\r') {
			off++
		}
		line := 1 + strings.Count(orig[:off], "\n")
		stmts = append(stmts, statement{line: line, raw: orig[start:end], norm: norm})
		start = end + 1
	}
	for i := 0; i < len(masked); i++ {
		if masked[i] == ';' {
			flush(i)
		}
	}
	if start < len(masked) {
		flush(len(masked))
	}
	return stmts
}

var (
	reCreateIndex = regexp.MustCompile(`^CREATE (UNIQUE )?INDEX\b`)
	reConcurrent  = regexp.MustCompile(`\bCONCURRENTLY\b`)
	reLockTable   = regexp.MustCompile(`^LOCK( TABLE)?\b`)
	reAlterTable  = regexp.MustCompile(`^ALTER TABLE (IF EXISTS )?(ONLY )?("?[\w$.]+"?)\s*(.*)$`)
	// reCreateTable captures the table name from a CREATE TABLE so
	// indexes on a just-created table can be recognised as lock-safe.
	// TEMPORARY/UNLOGGED tables are matched too (the qualifier sits
	// between CREATE and TABLE) but their indexes are equally safe.
	reCreateTable = regexp.MustCompile(`^CREATE (?:(?:GLOBAL|LOCAL) )?(?:TEMP|TEMPORARY|UNLOGGED) TABLE (?:IF NOT EXISTS )?("?[\w$.]+"?)|^CREATE TABLE (?:IF NOT EXISTS )?("?[\w$.]+"?)`)
	// reIndexTarget captures the table an index is built on. The
	// optional index-name group is skipped when absent (CREATE INDEX
	// ON tbl ...); ONLY is consumed so the table name is captured
	// either way.
	reIndexTarget = regexp.MustCompile(`^CREATE (?:UNIQUE )?INDEX (?:CONCURRENTLY )?(?:IF NOT EXISTS )?(?:\S+ )?ON (?:ONLY )?("?[\w$.]+"?)`)
)

// createdTableName reports the normalised name of the table a CREATE
// TABLE statement defines, or ("", false) if the statement is not a
// CREATE TABLE. The name is stripped of surrounding double quotes so
// it compares equal to an index target written without quotes.
func createdTableName(norm string) (string, bool) {
	m := reCreateTable.FindStringSubmatch(norm)
	if m == nil {
		return "", false
	}
	// Either the qualified-table branch (group 1) or the plain branch
	// (group 2) matched; take whichever is non-empty.
	name := m[1]
	if name == "" {
		name = m[2]
	}
	return normalizeIdent(name), name != ""
}

// indexTargetTable reports the normalised name of the table a CREATE
// INDEX builds on, or ("", false) if the target cannot be parsed.
func indexTargetTable(norm string) (string, bool) {
	m := reIndexTarget.FindStringSubmatch(norm)
	if m == nil {
		return "", false
	}
	return normalizeIdent(m[1]), m[1] != ""
}

// normalizeIdent strips surrounding double quotes from a (already
// upper-cased) identifier so quoted and unquoted spellings of the
// same name compare equal.
func normalizeIdent(s string) string {
	return strings.Trim(s, `"`)
}

// checkStatement applies every rule to one normalised statement.
// newTables holds the names of tables created earlier in the same
// migration; an index on one of them is exempt from the CONCURRENTLY
// rule because the table is brand-new and empty.
func checkStatement(file string, st statement, newTables map[string]struct{}) []Violation {
	var out []Violation
	add := func(rule Rule, msg string) {
		out = append(out, Violation{File: file, Line: st.line, Rule: rule, Message: msg})
	}

	switch {
	case reCreateIndex.MatchString(st.norm):
		if reConcurrent.MatchString(st.norm) {
			break
		}
		// A non-concurrent index on a table created earlier in this
		// same migration takes no meaningful lock: the table is
		// brand-new, empty, and invisible to other sessions until the
		// migration commits. CONCURRENTLY would in fact be illegal
		// here (it cannot run inside the implicit transaction a
		// multi-statement migration executes in). Only flag indexes
		// built on pre-existing tables, where the build holds a SHARE
		// lock that blocks writes for the duration of a full scan.
		if tbl, ok := indexTargetTable(st.norm); ok {
			if _, isNew := newTables[tbl]; isNew {
				break
			}
		}
		add(RuleIndexNotConcurrent,
			"CREATE INDEX on an existing table must use CONCURRENTLY so it does not block writes while the index builds")
	case reLockTable.MatchString(st.norm):
		add(RuleLockTable,
			"explicit LOCK TABLE is not allowed in a migration; it blocks all access to the table")
	case reAlterTable.MatchString(st.norm):
		out = append(out, checkAlterTable(file, st)...)
	}
	return out
}

// checkAlterTable splits the action list of an ALTER TABLE statement
// on top-level commas and applies the column-level rules to each
// action independently, so a multi-action ALTER TABLE is fully
// covered (Postgres allows `ADD COLUMN ..., ALTER COLUMN ...` in one
// statement).
func checkAlterTable(file string, st statement) []Violation {
	var out []Violation
	m := reAlterTable.FindStringSubmatch(st.norm)
	if m == nil {
		return out
	}
	actions := splitTopLevelCommas(m[4])
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}
		out = append(out, checkAlterAction(file, st.line, action)...)
	}
	return out
}

var (
	reAddColumn    = regexp.MustCompile(`^ADD (COLUMN )?(IF NOT EXISTS )?`)
	reAlterColType = regexp.MustCompile(`^ALTER (COLUMN )?("?[\w$]+"?|\S+) (SET DATA )?TYPE\b`)
	reDropColumn   = regexp.MustCompile(`^DROP (COLUMN )?(IF EXISTS )?`)
	reNotNull      = regexp.MustCompile(`\bNOT NULL\b`)
	reDefault      = regexp.MustCompile(`\bDEFAULT\b`)
	// Tokens that follow ADD/DROP for non-column actions, so an
	// implicit-keyword form (`ADD <ident>` / `DROP <ident>`) is not
	// mistaken for a column action.
	nonColumnAfterAddDrop = map[string]struct{}{
		"CONSTRAINT": {}, "PRIMARY": {}, "UNIQUE": {}, "FOREIGN": {},
		"CHECK": {}, "EXCLUDE": {}, "DEFAULT": {}, "GENERATED": {},
	}
)

// checkAlterAction applies the per-action rules: ADD COLUMN NOT NULL
// without DEFAULT, ALTER COLUMN TYPE, and DROP COLUMN.
func checkAlterAction(file string, line int, action string) []Violation {
	var out []Violation
	add := func(rule Rule, msg string) {
		out = append(out, Violation{File: file, Line: line, Rule: rule, Message: msg})
	}
	fields := strings.Fields(action)

	switch {
	case reAlterColType.MatchString(action):
		add(RuleAlterColumnType,
			"ALTER COLUMN ... TYPE rewrites the table under ACCESS EXCLUSIVE; use the OnlineMigrator shadow-table path instead")
	case reAddColumn.MatchString(action) && isColumnAction(fields):
		if reNotNull.MatchString(action) && !reDefault.MatchString(action) {
			add(RuleAddColumnNotNullNoDefault,
				"ADD COLUMN ... NOT NULL without DEFAULT rewrites every row; add a DEFAULT or split the change")
		}
	case reDropColumn.MatchString(action) && isColumnAction(fields):
		add(RuleDropColumn,
			"raw DROP COLUMN breaks rolling deploys; deprecate the column (stop reading, then writing) before dropping")
	}
	return out
}

// isColumnAction reports whether an ADD/DROP action targets a column
// (explicitly via the COLUMN keyword or implicitly via `ADD <ident>`)
// rather than a constraint or other object.
func isColumnAction(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	// fields[0] is ADD or DROP.
	next := fields[1]
	if next == "COLUMN" {
		return true
	}
	if next == "IF" {
		// ADD IF NOT EXISTS / DROP IF EXISTS -> the object is a column
		// when the COLUMN keyword is absent (implicit-column form).
		return true
	}
	_, nonCol := nonColumnAfterAddDrop[next]
	return !nonCol
}

// splitTopLevelCommas splits s on commas that are not nested inside
// parentheses, so `ADD COLUMN a int DEFAULT (1+2), ADD COLUMN b int`
// yields two actions rather than three.
func splitTopLevelCommas(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// maskSQL returns a copy of sql with the contents of line comments,
// block comments (nesting supported, per Postgres), single-quoted
// string literals, and dollar-quoted bodies replaced by spaces.
// Newlines are preserved so byte offsets and therefore line numbers
// are identical to the original. The result is the same length as
// the input.
func maskSQL(sql string) string {
	b := []byte(sql)
	out := make([]byte, len(b))
	for i := range out {
		out[i] = b[i]
	}
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	i := 0
	for i < len(b) {
		switch {
		case b[i] == '-' && i+1 < len(b) && b[i+1] == '-':
			j := i + 2
			for j < len(b) && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			j := i + 2
			depth := 1
			for j < len(b) && depth > 0 {
				if b[j] == '/' && j+1 < len(b) && b[j+1] == '*' {
					depth++
					j += 2
					continue
				}
				if b[j] == '*' && j+1 < len(b) && b[j+1] == '/' {
					depth--
					j += 2
					continue
				}
				j++
			}
			blank(i, j)
			i = j
		case (b[i] == 'E' || b[i] == 'e') && i+1 < len(b) && b[i+1] == '\'' &&
			(i == 0 || !isIdentByte(b[i-1])):
			// Postgres escape string `E'...'`: a backslash escapes the
			// next byte, so `\'` is a literal quote, not a terminator.
			// Blank the leading E together with the string body.
			j := scanQuoted(b, i+1, true)
			blank(i, j)
			i = j
		case b[i] == '\'':
			// Standard string literal: backslashes are literal and only
			// a doubled `''` escapes a quote.
			j := scanQuoted(b, i, false)
			blank(i, j)
			i = j
		case b[i] == '$':
			if tag, ok := dollarTag(b, i); ok {
				end := findDollarClose(b, i+len(tag), tag)
				blank(i, end)
				i = end
				continue
			}
			i++
		default:
			i++
		}
	}
	return string(out)
}

// scanQuoted returns the index just past the closing quote of the
// single-quoted string whose opening quote is at b[q]. A doubled
// quote (two apostrophes) is always an embedded quote, not a
// terminator. When escape is true (a Postgres E'...' string) a
// backslash also escapes the following byte, so a backslash-quote
// does not terminate the string. An
// unterminated string scans to EOF, which masks the remainder — the
// safe direction (the trailing text cannot then trip a rule).
func scanQuoted(b []byte, q int, escape bool) int {
	j := q + 1
	for j < len(b) {
		if escape && b[j] == '\\' && j+1 < len(b) {
			j += 2
			continue
		}
		if b[j] == '\'' {
			if j+1 < len(b) && b[j+1] == '\'' {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return j
}

// isIdentByte reports whether c can appear in a SQL identifier, used
// to ensure an `E'...'` escape-string prefix is a standalone token
// and not the tail of an identifier (e.g. the `e` in `code'x'`).
func isIdentByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// dollarTag returns the dollar-quote opening tag (e.g. "$$" or
// "$func$") starting at b[i], if b[i] opens one. The tag is
// `$[A-Za-z_][A-Za-z0-9_]*$` or the empty-tag `$$`.
func dollarTag(b []byte, i int) (string, bool) {
	if i >= len(b) || b[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(b) {
		c := b[j]
		if c == '$' {
			return string(b[i : j+1]), true
		}
		isIdent := c == '_' ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9' && j > i+1)
		if !isIdent {
			return "", false
		}
		j++
	}
	return "", false
}

// findDollarClose returns the index just past the closing dollar tag
// that matches tag, searching from from. If no close is found the
// end of the buffer is returned (an unterminated dollar quote masks
// to EOF, which is the safe behaviour).
func findDollarClose(b []byte, from int, tag string) int {
	idx := strings.Index(string(b[from:]), tag)
	if idx < 0 {
		return len(b)
	}
	return from + idx + len(tag)
}

// BaselineFromFS lists every `.up.sql` file at the root of fsys,
// sorted. It is the helper the CLI uses to build the default
// baseline of pre-existing migrations when no explicit baseline file
// is supplied.
func BaselineFromFS(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migration dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
