package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// This file holds the public SCIM 2.0 conformance vectors (RFC 7643 /
// 7644) the provisioning service is hardened against, organised by the
// Okta/Entra payload quirk each group exercises. The cases are derived
// from the RFCs and the published Okta / Microsoft Entra SCIM
// integration guides — NOT from a live tenant. The companion document
// SCIM_CERTIFICATION.md enumerates the live-tenant matrix to run once
// real Okta/Entra dev-tenant credentials are provided.

// --- Filter grammar: every comparison operator (RFC 7644 §3.4.2.2) --------

// TestFilterEveryComparisonOperatorParses asserts every RFC comparison
// operator parses, in lower/upper/mixed case, and that `pr` is the only
// one accepted without a value.
func TestFilterEveryComparisonOperatorParses(t *testing.T) {
	t.Parallel()
	binary := []string{"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
	for _, op := range binary {
		op := op
		for _, cased := range []string{op, upper(op), title(op)} {
			cased := cased
			t.Run("binary/"+cased, func(t *testing.T) {
				t.Parallel()
				if _, err := parseFilterExpr(fmt.Sprintf(`userName %s "x"`, cased)); err != nil {
					t.Errorf("parseFilterExpr(userName %s \"x\"): %v", cased, err)
				}
				// A binary operator without a value is malformed.
				if _, err := parseFilterExpr(fmt.Sprintf(`userName %s`, cased)); err == nil {
					t.Errorf("parseFilterExpr(userName %s): expected error for missing value", cased)
				}
			})
		}
	}
	for _, cased := range []string{"pr", "PR", "Pr"} {
		cased := cased
		t.Run("presence/"+cased, func(t *testing.T) {
			t.Parallel()
			if _, err := parseFilterExpr(`emails ` + cased); err != nil {
				t.Errorf("parseFilterExpr(emails %s): %v", cased, err)
			}
		})
	}
}

// TestFilterOperatorSemantics evaluates each operator against a concrete
// user so the match semantics — not just the parse — are pinned. String
// comparisons are case-insensitive (caseExact=false default); ordering
// operators compare lexicographically.
func TestFilterOperatorSemantics(t *testing.T) {
	t.Parallel()
	u := SCIMUser{
		UserName:    "alice@example.com",
		DisplayName: "Alice Smith",
		ExternalID:  "okta-100",
		Active:      boolPtr(true),
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{`userName eq "ALICE@EXAMPLE.COM"`, true}, // case-insensitive eq
		{`userName eq "bob@example.com"`, false},
		{`userName ne "bob@example.com"`, true},
		{`userName ne "alice@example.com"`, false},
		{`displayName co "smith"`, true}, // case-insensitive contains
		{`displayName co "jones"`, false},
		{`userName sw "alice"`, true},
		{`userName sw "bob"`, false},
		{`userName ew ".com"`, true},
		{`userName ew ".org"`, false},
		{`externalId pr`, true},
		{`displayName pr`, true},
		{`userName gt "a"`, true}, // "alice..." > "a"
		{`userName ge "alice@example.com"`, true},
		{`userName lt "z"`, true},
		{`userName le "alice@example.com"`, true},
		{`active eq "true"`, true},
		{`active eq "false"`, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.filter, func(t *testing.T) {
			t.Parallel()
			expr, err := parseFilterExpr(tc.filter)
			if err != nil {
				t.Fatalf("parseFilterExpr(%q): %v", tc.filter, err)
			}
			if got := expr.matchUser(u); got != tc.want {
				t.Errorf("matchUser(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// TestFilterAbsentAttributeSemantics pins how operators behave when the
// target attribute is absent (empty): `pr` is false, and a non-empty
// comparand never matches an absent value.
func TestFilterAbsentAttributeSemantics(t *testing.T) {
	t.Parallel()
	// No displayName / externalId set.
	u := SCIMUser{UserName: "noprofile@example.com"}
	cases := []struct {
		filter string
		want   bool
	}{
		{`displayName pr`, false},
		{`externalId pr`, false},
		{`displayName eq "x"`, false},
		{`displayName co "x"`, false},
		{`displayName sw "x"`, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.filter, func(t *testing.T) {
			t.Parallel()
			expr, err := parseFilterExpr(tc.filter)
			if err != nil {
				t.Fatalf("parseFilterExpr(%q): %v", tc.filter, err)
			}
			if got := expr.matchUser(u); got != tc.want {
				t.Errorf("matchUser(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// TestFilterLogicalGrammarVectors exercises boolean composition,
// precedence, parenthesisation, not(...), URN-qualified attribute paths,
// quoted-string escapes, and a battery of malformed inputs that must be
// rejected without panicking.
func TestFilterLogicalGrammarVectors(t *testing.T) {
	t.Parallel()
	valid := []string{
		`userName eq "a" and displayName co "b"`,
		`userName eq "a" or userName eq "b"`,
		`userName eq "a" and displayName co "b" or active eq "true"`, // (a and b) or c
		`not (userName eq "a")`,
		`not(userName eq "a")`,
		`not (not (userName eq "a"))`, // nested negation
		`(userName eq "a" or userName eq "b") and active eq "true"`,
		`((userName eq "a"))`,                                            // redundant nesting
		`userName eq "a" and (displayName co "b" or displayName co "c")`, // nested group
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"`,     // qualified attr
		`URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:userName eq "a"`,     // qualified attr with upper-cased URN prefix (canonicalAttr strips it case-insensitively at eval time — see TestQualifiedAttributePathCaseInsensitive)
		`userName eq "value with spaces and \"quotes\""`,                 // escaped quote
		`userName eq "back\\slash"`,                                      // escaped backslash
		`userName eq bareword`,                                           // unquoted value
		`name.givenName eq "Alice"`,                                      // sub-attribute path
		`userName eq "and"`,                                              // keyword as a quoted value
		`userName eq "not"`,
	}
	for _, f := range valid {
		f := f
		t.Run("valid/"+f, func(t *testing.T) {
			t.Parallel()
			if _, err := parseFilterExpr(f); err != nil {
				t.Errorf("parseFilterExpr(%q): unexpected error %v", f, err)
			}
		})
	}

	malformed := []string{
		``,
		`   `,
		`userName`,
		`userName eq`,
		`userName xx "a"`,
		`eq "a"`,
		`userName eq "unterminated`,
		`(userName eq "a"`,
		`userName eq "a")`,
		`not userName eq "a"`,
		`userName eq "a" and`,
		`userName eq "a" or`,
		`userName eq "a" "b"`,
		`userName[type eq "work"]`, // valuePath unsupported in filters
		`emails[type eq "work"].value eq "x@y.z"`, // nested valuePath unsupported
		`and userName eq "a"`,
		`or userName eq "a"`,
		`() `,
		`not ()`,
	}
	for _, f := range malformed {
		f := f
		t.Run("malformed/"+f, func(t *testing.T) {
			t.Parallel()
			if _, err := parseFilterExpr(f); err == nil {
				t.Errorf("parseFilterExpr(%q): expected error, got nil", f)
			}
		})
	}
}

// --- Pushdown vs in-memory parity (the active/emails fix) ----------------

// TestListUsersFilterParityAcrossPaths is the regression guard for the
// pushdown gap: a single eq/co/sw clause on an attribute the repository
// cannot index (active, the bare `emails` path, name.* sub-paths) must
// return the SAME result through ListUsers as evaluating the parsed
// expression in memory — never an empty page because the clause "looked
// pushdownable". Backed attributes (userName, displayName, externalId,
// emails.value) continue to resolve via the indexed path.
func TestListUsersFilterParityAcrossPaths(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()

	seed := []SCIMUser{
		{UserName: "alice@example.com", DisplayName: "Alice Smith", ExternalID: "okta-1", Active: boolPtr(true)},
		{UserName: "bob@example.com", DisplayName: "Bob Jones", ExternalID: "okta-2", Active: boolPtr(true)},
		{UserName: "carol@example.com", DisplayName: "Carol Smith", Active: boolPtr(false)},
	}
	for _, su := range seed {
		if _, err := svc.CreateUser(ctx, tid, su); err != nil {
			t.Fatalf("CreateUser(%s): %v", su.UserName, err)
		}
	}

	cases := []struct {
		name   string
		filter string
		want   int
	}{
		{"active eq true", `active eq "true"`, 2},
		{"active eq false", `active eq "false"`, 1},
		{"emails eq (bare path)", `emails eq "alice@example.com"`, 1},
		{"emails.value eq (backed)", `emails.value eq "bob@example.com"`, 1},
		{"emails co (bare path)", `emails co "example.com"`, 3},
		{"userName eq (backed fast path)", `userName eq "alice@example.com"`, 1},
		{"displayName co (backed)", `displayName co "smith"`, 2},
		{"externalId eq (backed)", `externalId eq "okta-2"`, 1},
		{"externalId pr (in-memory)", `externalId pr`, 2},
		{"id pr (in-memory, all have ids)", `id pr`, 3},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			list, err := svc.ListUsers(ctx, tid, tc.filter, 1, 100)
			if err != nil {
				t.Fatalf("ListUsers(%q): %v", tc.filter, err)
			}
			if list.TotalResults != tc.want {
				t.Errorf("ListUsers(%q) TotalResults = %d, want %d", tc.filter, list.TotalResults, tc.want)
			}
			if list.ItemsPerPage != tc.want {
				t.Errorf("ListUsers(%q) ItemsPerPage = %d, want %d", tc.filter, list.ItemsPerPage, tc.want)
			}
		})
	}
}

// --- Pagination boundaries (RFC 7644 §3.4.2) ------------------------------

// TestPaginationBoundaries pins the startIndex/count window normalisation
// across both the indexed (unfiltered) and in-memory (filtered) list
// paths: 1-based indexing, a startIndex past the end yields an empty page
// with a stable total, count<=0 falls back to the default, and the
// reported StartIndex echoes the (normalised) request.
func TestPaginationBoundaries(t *testing.T) {
	t.Parallel()
	const total = 7
	cases := []struct {
		name           string
		filter         string // "" exercises the indexed path; a co-clause the in-memory path
		startIndex     int
		count          int
		wantItems      int
		wantTotal      int
		wantStartIndex int
	}{
		{"first page indexed", "", 1, 3, 3, total, 1},
		{"middle page indexed", "", 4, 3, 3, total, 4},
		{"partial last page indexed", "", 7, 3, 1, total, 7},
		{"startIndex past end indexed", "", 100, 3, 0, total, 100},
		{"startIndex zero normalises to one", "", 0, 3, 3, total, 1},
		{"negative startIndex normalises to one", "", -5, 3, 3, total, 1},
		{"count zero falls back to default", "", 1, 0, total, total, 1},
		{"exact boundary indexed", "", 6, 2, 2, total, 6},
		{"first page in-memory", `active eq "true"`, 1, 3, 3, total, 1},
		{"partial last page in-memory", `active eq "true"`, 7, 3, 1, total, 7},
		{"startIndex past end in-memory", `active eq "true"`, 100, 3, 0, total, 100},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, tid := newSCIMService(t)
			ctx := context.Background()
			for i := 0; i < total; i++ {
				if _, err := svc.CreateUser(ctx, tid, SCIMUser{
					UserName: fmt.Sprintf("u%02d@example.com", i),
					Active:   boolPtr(true),
				}); err != nil {
					t.Fatalf("seed %d: %v", i, err)
				}
			}
			list, err := svc.ListUsers(ctx, tid, tc.filter, tc.startIndex, tc.count)
			if err != nil {
				t.Fatalf("ListUsers: %v", err)
			}
			if list.TotalResults != tc.wantTotal {
				t.Errorf("TotalResults = %d, want %d", list.TotalResults, tc.wantTotal)
			}
			if list.ItemsPerPage != tc.wantItems || len(list.Resources) != tc.wantItems {
				t.Errorf("ItemsPerPage = %d / len = %d, want %d", list.ItemsPerPage, len(list.Resources), tc.wantItems)
			}
			if list.StartIndex != tc.wantStartIndex {
				t.Errorf("StartIndex = %d, want %d", list.StartIndex, tc.wantStartIndex)
			}
		})
	}
}

// TestPaginationCoversEverythingExactlyOnce pages a filtered result set
// in small windows and asserts every match is returned exactly once with
// a stable total — the property an IdP relies on when it walks /Users.
func TestPaginationCoversEverythingExactlyOnce(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	const total = 9
	for i := 0; i < total; i++ {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{
			UserName: fmt.Sprintf("page-%02d@example.com", i),
			Active:   boolPtr(true),
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	seen := map[string]bool{}
	for start := 1; start <= total; start += 2 {
		page, err := svc.ListUsers(ctx, tid, `userName co "page-"`, start, 2)
		if err != nil {
			t.Fatalf("ListUsers(start=%d): %v", start, err)
		}
		if page.TotalResults != total {
			t.Errorf("start=%d: TotalResults = %d, want %d", start, page.TotalResults, total)
		}
		for _, r := range page.Resources {
			su, ok := r.(SCIMUser)
			if !ok {
				t.Fatalf("resource type %T, want SCIMUser", r)
			}
			if seen[su.ID] {
				t.Errorf("user %s returned on more than one page", su.ID)
			}
			seen[su.ID] = true
		}
	}
	if len(seen) != total {
		t.Errorf("walked %d distinct users, want %d", len(seen), total)
	}
}

// --- Group membership: Okta valuePath vs Entra value-array ---------------

// TestGroupMemberRemovalShapes is the regression guard for silently
// dropped de-provisioning: a member must be removable through BOTH the
// Okta valuePath shape (`members[value eq "<id>"]`, no value body) and
// the Microsoft Entra value-array shape (`path:"members"` with a value).
// Each removal must also be idempotent on replay.
func TestGroupMemberRemovalShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		removeOp func(memberID string) SCIMPatchOp
		wantNoop bool // true => op shape should leave membership intact
	}{
		{
			name: "okta valuePath",
			removeOp: func(id string) SCIMPatchOp {
				return SCIMPatchOp{Op: "remove", Path: `members[value eq "` + id + `"]`}
			},
		},
		{
			name: "okta valuePath URN-qualified",
			removeOp: func(id string) SCIMPatchOp {
				return SCIMPatchOp{Op: "remove", Path: SCIMSchemaGroup + `:members[value eq "` + id + `"]`}
			},
		},
		{
			name: "entra value-array",
			removeOp: func(id string) SCIMPatchOp {
				return SCIMPatchOp{Op: "remove", Path: "members", Value: []any{map[string]any{"value": id}}}
			},
		},
		{
			name: "entra value-array URN-qualified path",
			removeOp: func(id string) SCIMPatchOp {
				return SCIMPatchOp{Op: "remove", Path: SCIMSchemaGroup + ":members", Value: []any{map[string]any{"value": id}}}
			},
		},
		{
			name: "unrelated valuePath is a no-op",
			removeOp: func(id string) SCIMPatchOp {
				return SCIMPatchOp{Op: "remove", Path: `displayName[value eq "` + id + `"]`}
			},
			wantNoop: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := memory.NewStore()
			tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
				Name: "members", Slug: "members-" + tc.name, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
			})
			if err != nil {
				t.Fatalf("seed tenant: %v", err)
			}
			roles := memory.NewRoleRepository(s)
			svc := NewSCIMService(memory.NewUserRepository(s), roles, memory.NewAuditLogRepository(s))
			ctx := context.Background()

			u, err := svc.CreateUser(ctx, tn.ID, SCIMUser{UserName: "member@example.com"})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			g, err := svc.CreateGroup(ctx, tn.ID, SCIMGroup{DisplayName: "Admins"})
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			gid := uuidFromString(g.ID)
			uid := uuidFromString(u.ID)

			if _, err := svc.PatchGroup(ctx, tn.ID, gid, []SCIMPatchOp{
				{Op: "add", Path: "members", Value: []any{map[string]any{"value": u.ID}}},
			}); err != nil {
				t.Fatalf("add member: %v", err)
			}
			if n := userRoleCount(t, roles, uid); n != 1 {
				t.Fatalf("after add: roles = %d, want 1", n)
			}

			// Remove twice to assert idempotency.
			for i := 0; i < 2; i++ {
				if _, err := svc.PatchGroup(ctx, tn.ID, gid, []SCIMPatchOp{tc.removeOp(u.ID)}); err != nil {
					t.Fatalf("remove #%d: %v", i, err)
				}
			}
			got := userRoleCount(t, roles, uid)
			want := 0
			if tc.wantNoop {
				want = 1
			}
			if got != want {
				t.Errorf("after remove: roles = %d, want %d", got, want)
			}
		})
	}
}

// TestMemberValuePathTarget unit-tests the valuePath parser in isolation
// across the shapes Okta/Entra emit and the malformed ones that must not
// be mistaken for a member removal.
func TestMemberValuePathTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path   string
		want   string
		wantOK bool
	}{
		{`members[value eq "abc"]`, "abc", true},
		{`members[value eq "ABC-123"]`, "abc-123", true}, // canonicalAttr lowercases; uuid parse is case-insensitive
		{SCIMSchemaGroup + `:members[value eq "abc"]`, "abc", true},
		{`MEMBERS[VALUE EQ "abc"]`, "abc", true},
		{`members[ value eq "abc" ]`, "abc", true},
		{`members`, "", false},
		{`displayName[value eq "abc"]`, "", false},
		{`members[type eq "direct"]`, "", false},
		{`members[value eq ""]`, "", false},
		{`members[value co "abc"]`, "", false},
		{`members[value eq "abc"`, "", false}, // missing close bracket
		{``, "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			got, ok := memberValuePathTarget(tc.path)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("memberValuePathTarget(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestCanonicalAttrPrefixCaseInsensitive pins that the core-schema URN
// prefix is stripped case-insensitively (RFC 8141 §2 — URN namespace
// identifiers are case-insensitive), so a qualified attribute path
// resolves to the same short attribute regardless of the casing an IdP
// uses for the `urn:...:User:`/`urn:...:Group:` prefix.
func TestCanonicalAttrPrefixCaseInsensitive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{SCIMSchemaUser + ":userName", "username"},
		{"URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:userName", "username"},
		{"Urn:Ietf:Params:Scim:Schemas:Core:2.0:User:displayName", "displayname"},
		{SCIMSchemaGroup + ":members", "members"},
		{"URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:GROUP:members", "members"},
		{"userName", "username"}, // unqualified, unchanged but lowered
		{"name.givenName", "name.givenname"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := canonicalAttr(tc.in); got != tc.want {
				t.Errorf("canonicalAttr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestQualifiedAttributePathCaseInsensitive proves the case-insensitive
// prefix handling end to end: a filter whose attribute carries an
// upper-cased schema URN must still match through ListUsers, not just
// parse. This is the eval-time guarantee the grammar-vector comment
// refers to.
func TestQualifiedAttributePathCaseInsensitive(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "qualified@example.com", Active: boolPtr(true)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	filters := []string{
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "qualified@example.com"`,
		`URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:userName eq "qualified@example.com"`,
	}
	for _, f := range filters {
		f := f
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			list, err := svc.ListUsers(ctx, tid, f, 1, 10)
			if err != nil {
				t.Fatalf("ListUsers(%q): %v", f, err)
			}
			if list.TotalResults != 1 {
				t.Errorf("ListUsers(%q) TotalResults = %d, want 1 (qualified path must resolve regardless of URN casing)", f, list.TotalResults)
			}
		})
	}
}

// --- Idempotency / retry semantics (RFC 7644 §3.5.1 PUT, §3.5.2 PATCH) ---

// TestPutIsIdempotent verifies that replaying the same PUT converges on
// the same observable resource state — the property an IdP relies on
// when it retries a full-resource sync after a transient failure. (The
// weak meta.version intentionally rotates on every write because it
// folds in UpdatedAt; idempotency is about the resource fields, not the
// validator, so we assert on the projected representation.)
func TestPutIsIdempotent(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	created, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "put@example.com", DisplayName: "Orig", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	desired := SCIMUser{UserName: "put@example.com", DisplayName: "Renamed", ExternalID: "ext-1", Active: boolPtr(false)}

	var prev string
	for i := 0; i < 3; i++ {
		out, err := svc.UpdateUser(ctx, tid, uid, desired)
		if err != nil {
			t.Fatalf("UpdateUser #%d: %v", i, err)
		}
		// Compare the field-bearing projection (everything except the
		// time-derived meta), which must be identical across replays.
		out.Meta = nil
		raw, _ := json.Marshal(out)
		if i > 0 && string(raw) != prev {
			t.Errorf("replay #%d diverged: %s != %s", i, raw, prev)
		}
		prev = string(raw)
	}
	final, err := svc.GetUser(ctx, tid, uid)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if final.DisplayName != "Renamed" || final.ExternalID != "ext-1" || final.Active == nil || *final.Active {
		t.Errorf("final state = %+v, want Renamed/ext-1/inactive", final)
	}
}

// TestPatchReplayConvergesToSameState verifies repeated PATCH replays of
// a deactivation converge on the same persisted state (active=false).
func TestPatchReplayConvergesToSameState(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	created, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "patch@example.com", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	for i := 0; i < 3; i++ {
		out, err := svc.PatchUser(ctx, tid, uid, []SCIMPatchOp{{Op: "replace", Path: "active", Value: false}})
		if err != nil {
			t.Fatalf("PatchUser #%d: %v", i, err)
		}
		if out.Active == nil || *out.Active {
			t.Fatalf("replay #%d left user active", i)
		}
	}
}

// TestCreateUserDuplicateRejected verifies a re-POST of an existing
// userName surfaces a conflict (so the IdP's create-after-failed-dedup
// does not silently produce a second account) rather than a duplicate.
func TestCreateUserDuplicateRejected(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "dup@example.com"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	_, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "dup@example.com"})
	if err == nil {
		t.Fatal("expected a conflict re-creating an existing userName")
	}
}

// --- Bulk de-provisioning: idempotent DELETE, ordering, FailOnErrors -----

// TestBulkDeprovisionIdempotentDelete verifies a bulk DELETE of a user
// succeeds and a replayed DELETE in a later batch is still safe (the
// soft-delete is idempotent), so an IdP retrying an offboarding batch
// does not error out.
func TestBulkDeprovisionIdempotentDelete(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	created, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: "leaver@example.com", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	op := SCIMBulkOperation{Method: "DELETE", Path: "/Users/" + created.ID}
	for i := 0; i < 2; i++ {
		resp, err := svc.Bulk(ctx, tid, SCIMBulkRequest{
			Schemas:    []string{SCIMSchemaBulkRequest},
			Operations: []SCIMBulkOperation{op},
		})
		if err != nil {
			t.Fatalf("Bulk #%d: %v", i, err)
		}
		if resp.Operations[0].Status != "204" {
			t.Fatalf("bulk DELETE #%d status = %s, want 204 (%+v)", i, resp.Operations[0].Status, resp.Operations[0].Response)
		}
	}
	got, err := svc.GetUser(ctx, tid, uuidFromString(created.ID))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Active == nil || *got.Active {
		t.Error("user should be de-provisioned (inactive) after bulk DELETE")
	}
}

// TestBulkFailOnErrorsStops verifies that once FailOnErrors failures
// accrue the remaining operations are skipped (RFC 7644 §3.7.3), so a
// large offboarding batch can be told to abort early on trouble.
func TestBulkFailOnErrorsStops(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()

	good, _ := json.Marshal(SCIMUser{UserName: "ok@example.com", Active: boolPtr(true)})
	bad, _ := json.Marshal(SCIMUser{Active: boolPtr(true)}) // missing userName -> 400

	resp, err := svc.Bulk(ctx, tid, SCIMBulkRequest{
		Schemas:      []string{SCIMSchemaBulkRequest},
		FailOnErrors: 1,
		Operations: []SCIMBulkOperation{
			{Method: "POST", Path: "/Users", BulkID: "a", Data: bad},  // fails -> reaches FailOnErrors
			{Method: "POST", Path: "/Users", BulkID: "b", Data: good}, // must be skipped
		},
	})
	if err != nil {
		t.Fatalf("Bulk: %v", err)
	}
	if len(resp.Operations) != 1 {
		t.Fatalf("processed %d operations, want 1 (FailOnErrors=1 must stop after the first failure)", len(resp.Operations))
	}
	if resp.Operations[0].Status != "400" {
		t.Errorf("first op status = %s, want 400", resp.Operations[0].Status)
	}
	// The skipped create must not have produced a user.
	list, err := svc.ListUsers(ctx, tid, `userName eq "ok@example.com"`, 1, 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if list.TotalResults != 0 {
		t.Errorf("skipped create still produced a user: TotalResults = %d", list.TotalResults)
	}
}

// TestBulkOperationsAppliedInOrder verifies a create-then-deactivate
// sequence within one batch is applied in request order against the same
// resolved resource (bulkId reference), the basic ordering guarantee a
// JML batch depends on.
func TestBulkOperationsAppliedInOrder(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()

	userData, _ := json.Marshal(SCIMUser{UserName: "ordered@example.com", Active: boolPtr(true)})
	patchData, _ := json.Marshal(SCIMPatchRequest{
		Schemas:    []string{SCIMSchemaPatch},
		Operations: []SCIMPatchOp{{Op: "replace", Path: "active", Value: false}},
	})
	resp, err := svc.Bulk(ctx, tid, SCIMBulkRequest{
		Schemas: []string{SCIMSchemaBulkRequest},
		Operations: []SCIMBulkOperation{
			{Method: "POST", Path: "/Users", BulkID: "x", Data: userData},
			{Method: "PATCH", Path: "/Users/bulkId:x", Data: patchData},
		},
	})
	if err != nil {
		t.Fatalf("Bulk: %v", err)
	}
	if resp.Operations[0].Status != "201" || resp.Operations[1].Status != "200" {
		t.Fatalf("statuses = %s/%s, want 201/200", resp.Operations[0].Status, resp.Operations[1].Status)
	}
	list, _ := svc.ListUsers(ctx, tid, `userName eq "ordered@example.com"`, 1, 10)
	if list.TotalResults != 1 {
		t.Fatalf("created user not found")
	}
	got := list.Resources[0].(SCIMUser)
	if got.Active == nil || *got.Active {
		t.Error("create-then-deactivate batch left the user active; ops not applied in order")
	}
}

// --- small helpers --------------------------------------------------------

func userRoleCount(t *testing.T, roles repository.RoleRepository, userID uuid.UUID) int {
	t.Helper()
	urs, err := roles.GetUserRoles(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	return len(urs)
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func title(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
