package migrate

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// hasRule reports whether vs contains at least one violation of rule.
func hasRule(vs []Violation, rule Rule) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func rules(vs []Violation) []Rule {
	out := make([]Rule, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	return out
}

// TestValidator_RejectsAddColumnNotNullNoDefault covers the
// ADD COLUMN ... NOT NULL-without-DEFAULT rule, including the case
// where a DEFAULT is present (allowed) and a multi-action ALTER.
func TestValidator_RejectsAddColumnNotNullNoDefault(t *testing.T) {
	mv := NewMigrationValidator(nil)

	bad := "ALTER TABLE devices ADD COLUMN region text NOT NULL;"
	if vs := mv.ValidateContent("x.up.sql", bad); !hasRule(vs, RuleAddColumnNotNullNoDefault) {
		t.Fatalf("expected add-column-not-null-no-default, got %v", rules(vs))
	}

	// DEFAULT present -> safe (PG11+ fast default).
	ok := "ALTER TABLE devices ADD COLUMN region text NOT NULL DEFAULT 'us';"
	if vs := mv.ValidateContent("x.up.sql", ok); len(vs) != 0 {
		t.Fatalf("ADD COLUMN with DEFAULT should be allowed, got %v", rules(vs))
	}

	// Nullable add -> safe.
	nullable := "ALTER TABLE devices ADD COLUMN region text;"
	if vs := mv.ValidateContent("x.up.sql", nullable); len(vs) != 0 {
		t.Fatalf("nullable ADD COLUMN should be allowed, got %v", rules(vs))
	}

	// IF NOT EXISTS implicit-column form is still checked.
	ine := "ALTER TABLE devices ADD COLUMN IF NOT EXISTS region text NOT NULL;"
	if vs := mv.ValidateContent("x.up.sql", ine); !hasRule(vs, RuleAddColumnNotNullNoDefault) {
		t.Fatalf("expected violation for IF NOT EXISTS form, got %v", rules(vs))
	}
}

// TestValidator_MultiActionAlter ensures each action in a
// comma-separated ALTER TABLE is checked independently.
func TestValidator_MultiActionAlter(t *testing.T) {
	mv := NewMigrationValidator(nil)
	sql := "ALTER TABLE t ADD COLUMN a int, ALTER COLUMN b TYPE bigint, DROP COLUMN c;"
	vs := mv.ValidateContent("x.up.sql", sql)
	if !hasRule(vs, RuleAlterColumnType) {
		t.Errorf("expected alter-column-type, got %v", rules(vs))
	}
	if !hasRule(vs, RuleDropColumn) {
		t.Errorf("expected drop-column, got %v", rules(vs))
	}
	// `ADD COLUMN a int` is nullable -> no add-column violation.
	if hasRule(vs, RuleAddColumnNotNullNoDefault) {
		t.Errorf("did not expect add-column violation, got %v", rules(vs))
	}
}

// TestValidator_RejectsNonConcurrentIndex covers CREATE INDEX both
// with and without CONCURRENTLY, plus the UNIQUE variant.
func TestValidator_RejectsNonConcurrentIndex(t *testing.T) {
	mv := NewMigrationValidator(nil)

	cases := map[string]bool{ // sql -> expectViolation
		"CREATE INDEX idx_a ON t (a);":                          true,
		"CREATE UNIQUE INDEX idx_a ON t (a);":                   true,
		"CREATE INDEX CONCURRENTLY idx_a ON t (a);":             false,
		"CREATE UNIQUE INDEX CONCURRENTLY idx_a ON t (a);":      false,
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx ON t (a);": false,
	}
	for sql, want := range cases {
		vs := mv.ValidateContent("x.up.sql", sql)
		if got := hasRule(vs, RuleIndexNotConcurrent); got != want {
			t.Errorf("sql %q: want violation=%v, got %v (%v)", sql, want, got, rules(vs))
		}
	}
}

// TestValidator_RejectsAlterColumnType covers ALTER COLUMN ... TYPE
// and the SET DATA TYPE spelling.
func TestValidator_RejectsAlterColumnType(t *testing.T) {
	mv := NewMigrationValidator(nil)
	for _, sql := range []string{
		"ALTER TABLE t ALTER COLUMN c TYPE bigint;",
		"ALTER TABLE t ALTER COLUMN c SET DATA TYPE bigint;",
		"ALTER TABLE t ALTER c TYPE bigint;",
	} {
		if vs := mv.ValidateContent("x.up.sql", sql); !hasRule(vs, RuleAlterColumnType) {
			t.Errorf("sql %q: expected alter-column-type, got %v", sql, rules(vs))
		}
	}
	// SET NOT NULL / SET DEFAULT are not type changes.
	for _, sql := range []string{
		"ALTER TABLE t ALTER COLUMN c SET DEFAULT 1;",
		"ALTER TABLE t ALTER COLUMN c DROP DEFAULT;",
	} {
		if vs := mv.ValidateContent("x.up.sql", sql); hasRule(vs, RuleAlterColumnType) {
			t.Errorf("sql %q: unexpected alter-column-type, got %v", sql, rules(vs))
		}
	}
}

// TestValidator_RejectsLockTable covers explicit LOCK statements.
func TestValidator_RejectsLockTable(t *testing.T) {
	mv := NewMigrationValidator(nil)
	for _, sql := range []string{
		"LOCK TABLE t IN ACCESS EXCLUSIVE MODE;",
		"LOCK t;",
	} {
		if vs := mv.ValidateContent("x.up.sql", sql); !hasRule(vs, RuleLockTable) {
			t.Errorf("sql %q: expected lock-table, got %v", sql, rules(vs))
		}
	}
}

// TestValidator_RejectsDropColumn covers raw DROP COLUMN, including
// the implicit-keyword form, while leaving DROP CONSTRAINT alone.
func TestValidator_RejectsDropColumn(t *testing.T) {
	mv := NewMigrationValidator(nil)
	for _, sql := range []string{
		"ALTER TABLE t DROP COLUMN c;",
		"ALTER TABLE t DROP COLUMN IF EXISTS c;",
		"ALTER TABLE t DROP c;",
	} {
		if vs := mv.ValidateContent("x.up.sql", sql); !hasRule(vs, RuleDropColumn) {
			t.Errorf("sql %q: expected drop-column, got %v", sql, rules(vs))
		}
	}
	// DROP CONSTRAINT is not a column drop.
	if vs := mv.ValidateContent("x.up.sql", "ALTER TABLE t DROP CONSTRAINT t_pkey;"); hasRule(vs, RuleDropColumn) {
		t.Errorf("DROP CONSTRAINT should not trip drop-column, got %v", rules(vs))
	}
}

// TestValidator_IgnoresComments ensures keywords inside line and
// block comments do not trigger rules.
func TestValidator_IgnoresComments(t *testing.T) {
	mv := NewMigrationValidator(nil)
	sql := `-- CREATE INDEX idx ON t (a);
/* LOCK TABLE t;
   ALTER TABLE t DROP COLUMN c; */
CREATE TABLE ok (id int);`
	if vs := mv.ValidateContent("x.up.sql", sql); len(vs) != 0 {
		t.Fatalf("commented-out DDL should be ignored, got %v", rules(vs))
	}
}

// TestValidator_IgnoresStringAndDollarBodies ensures keywords inside
// string literals and dollar-quoted function bodies are not matched.
func TestValidator_IgnoresStringAndDollarBodies(t *testing.T) {
	mv := NewMigrationValidator(nil)
	sql := `INSERT INTO audit (msg) VALUES ('CREATE INDEX idx ON t (a)');
CREATE OR REPLACE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    LOCK TABLE t IN ACCESS EXCLUSIVE MODE;
    ALTER TABLE t DROP COLUMN c;
END;
$$;`
	if vs := mv.ValidateContent("x.up.sql", sql); len(vs) != 0 {
		t.Fatalf("DDL inside strings/dollar bodies should be ignored, got %v", rules(vs))
	}
}

// TestValidator_LineNumbers checks that the reported line points at
// the offending statement.
func TestValidator_LineNumbers(t *testing.T) {
	mv := NewMigrationValidator(nil)
	sql := "CREATE TABLE ok (id int);\n\nCREATE INDEX idx ON ok (id);\n"
	vs := mv.ValidateContent("x.up.sql", sql)
	if len(vs) != 1 {
		t.Fatalf("want 1 violation, got %d (%v)", len(vs), rules(vs))
	}
	if vs[0].Line != 3 {
		t.Errorf("want line 3, got %d", vs[0].Line)
	}
}

// TestValidator_Baseline confirms baselined files are skipped and
// non-baselined files are still checked through ValidateFiles.
func TestValidator_Baseline(t *testing.T) {
	fsys := fstest.MapFS{
		"001_old.up.sql":   {Data: []byte("CREATE INDEX idx ON t (a);")},
		"050_new.up.sql":   {Data: []byte("CREATE INDEX idx2 ON t (b);")},
		"050_new.down.sql": {Data: []byte("DROP INDEX idx2;")},
	}
	mv := NewMigrationValidator([]string{"001_old.up.sql"})

	// Baselined file alone -> no error.
	if err := mv.ValidateFiles(fsys, []string{"001_old.up.sql"}); err != nil {
		t.Fatalf("baselined file should pass, got %v", err)
	}
	// New file -> error.
	err := mv.ValidateFiles(fsys, []string{"050_new.up.sql"})
	if err == nil {
		t.Fatal("expected validation error for new file")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Violations) != 1 || ve.Violations[0].File != "050_new.up.sql" {
		t.Fatalf("unexpected violations: %v", ve.Violations)
	}
	// down.sql is never analysed.
	if err := mv.ValidateFiles(fsys, []string{"050_new.down.sql"}); err != nil {
		t.Fatalf("down files should be skipped, got %v", err)
	}
}

// TestBaselineFromFS lists only up.sql files, sorted.
func TestBaselineFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"002_b.up.sql":   {Data: []byte("")},
		"001_a.up.sql":   {Data: []byte("")},
		"001_a.down.sql": {Data: []byte("")},
		"notes.txt":      {Data: []byte("")},
	}
	got, err := BaselineFromFS(fsys)
	if err != nil {
		t.Fatalf("BaselineFromFS: %v", err)
	}
	want := []string{"001_a.up.sql", "002_b.up.sql"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("want %v, got %v", want, got)
	}
}

// TestValidator_RealMigrationsBaselineClean is a guard: the embedded
// migrations, when fully baselined, must produce zero violations —
// proving the baseline mechanism shields all pre-existing files.
func TestValidator_RealMigrationsBaselineClean(t *testing.T) {
	baseline, err := BaselineFromFS(SourceFS())
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	mv := NewMigrationValidator(baseline)
	if err := mv.ValidateFiles(SourceFS(), baseline); err != nil {
		t.Fatalf("fully-baselined embedded migrations should pass, got: %v", err)
	}
}
