package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// newSCIMServiceWithRevoker builds a SCIMService over a fresh memory
// store with a revocation publisher wired, returning the service, the
// seeded tenant id, and the capture publisher so a test can assert which
// users had their sessions revoked.
func newSCIMServiceWithRevoker(t *testing.T) (*SCIMService, uuid.UUID, *capturePublisher) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "SCIM Hardening", Slug: "scim-hardening", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	pub := newCapturePublisher()
	svc := NewSCIMService(
		memory.NewUserRepository(s),
		memory.NewRoleRepository(s),
		memory.NewAuditLogRepository(s),
		WithRevocationPublisher(pub),
	)
	return svc, tn.ID, pub
}

// count reports how many revocations were published for a user, so a
// test can assert idempotency (exactly one across repeated deactivates).
func (p *capturePublisher) count(userID uuid.UUID) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, id := range p.revoked {
		if id == userID {
			n++
		}
	}
	return n
}

// failingPublisher always fails, used to assert a publish failure is
// surfaced to the caller (so the IdP retries) without undoing the
// already-durable suspend.
type failingPublisher struct{}

func (failingPublisher) PublishRevocation(_ context.Context, _, _ uuid.UUID, _ string) error {
	return errors.New("broker unavailable")
}

func mustCreateActiveUser(t *testing.T, svc *SCIMService, tid uuid.UUID, userName string) uuid.UUID {
	t.Helper()
	u, err := svc.CreateUser(context.Background(), tid, SCIMUser{
		Schemas:  []string{SCIMSchemaUser},
		UserName: userName,
		Active:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", userName, err)
	}
	return uuidFromString(u.ID)
}

// --- Fix 1: de-provisioning revokes sessions on PATCH/PUT deactivation -----

// TestPatchDeactivationRevokesSessions covers the canonical Okta/Entra
// de-provision: a PATCH setting active=false must cut the user's live
// ZTNA sessions, exactly as a SCIM DELETE does.
func TestPatchDeactivationRevokesSessions(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "deact@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	}); err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if !pub.was(uid) {
		t.Fatal("expected a revocation on PATCH active=false")
	}
	if got := pub.reasons[uid]; got != "scim_user_deactivated" {
		t.Errorf("reason = %q, want scim_user_deactivated", got)
	}
}

// TestPutDeactivationRevokesSessions covers de-provisioning via a PUT
// (full replace) that flips active to false.
func TestPutDeactivationRevokesSessions(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "putdeact@example.com")

	if _, err := svc.UpdateUser(context.Background(), tid, uid, SCIMUser{
		UserName: "putdeact@example.com",
		Active:   boolPtr(false),
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if pub.count(uid) != 1 {
		t.Fatalf("revocations = %d, want 1 on PUT active=false", pub.count(uid))
	}
}

// TestPathlessAzureDeactivationRevokesSessions covers Microsoft Entra's
// path-less PATCH shape: {"op":"replace","value":{"active":false}}.
func TestPathlessAzureDeactivationRevokesSessions(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "azure@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Value: map[string]any{"active": false}},
	}); err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if pub.count(uid) != 1 {
		t.Fatalf("revocations = %d, want 1 on path-less active=false", pub.count(uid))
	}
}

// TestStringActiveDeactivationRevokesSessions covers IdPs that send the
// active flag as the string "false" rather than a JSON bool.
func TestStringActiveDeactivationRevokesSessions(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "strfalse@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: "false"},
	}); err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if pub.count(uid) != 1 {
		t.Fatalf("revocations = %d, want 1 on active=\"false\"", pub.count(uid))
	}
}

// TestRepeatedDeactivationIsRetrySafe verifies that re-sending
// active=false against an already-inactive user STILL publishes a
// revocation. This is the retry-safety property: an IdP that retries a
// deactivation after a transient downstream failure (e.g. the bridge
// sync failed on the first attempt, leaving the user already suspended)
// must not have its revocation silently dropped. The downstream
// revocation is idempotent, so the extra publish is harmless.
func TestRepeatedDeactivationIsRetrySafe(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "retry@example.com")

	for i := 0; i < 3; i++ {
		if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
			{Op: "replace", Path: "active", Value: false},
		}); err != nil {
			t.Fatalf("PatchUser #%d: %v", i, err)
		}
	}
	if pub.count(uid) != 3 {
		t.Fatalf("revocations = %d, want 3 (each explicit deactivation re-publishes for retry-safety)", pub.count(uid))
	}
}

// TestProfilePatchOnInactiveUserDoesNotRevoke verifies that a
// profile-only PATCH against an already-suspended user does NOT revoke:
// the revocation fires only when the request asserts active=false, not
// on every mutation of an inactive user.
func TestProfilePatchOnInactiveUserDoesNotRevoke(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "inactive-profile@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	}); err != nil {
		t.Fatalf("PatchUser deactivate: %v", err)
	}
	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "displayName", Value: "Renamed While Suspended"},
	}); err != nil {
		t.Fatalf("PatchUser profile: %v", err)
	}
	if pub.count(uid) != 1 {
		t.Fatalf("revocations = %d, want 1 (profile PATCH on inactive user must not revoke)", pub.count(uid))
	}
}

// TestReactivationDoesNotRevoke verifies that re-enabling a suspended
// user (active=true) never emits a revocation.
func TestReactivationDoesNotRevoke(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "react@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	}); err != nil {
		t.Fatalf("PatchUser deactivate: %v", err)
	}
	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: true},
	}); err != nil {
		t.Fatalf("PatchUser reactivate: %v", err)
	}
	if pub.count(uid) != 1 {
		t.Fatalf("revocations = %d, want 1 (reactivation must not revoke)", pub.count(uid))
	}
}

// TestNonStatusPatchDoesNotRevoke verifies that a profile-only PATCH
// (e.g. a display-name change) on an active user does not revoke.
func TestNonStatusPatchDoesNotRevoke(t *testing.T) {
	t.Parallel()
	svc, tid, pub := newSCIMServiceWithRevoker(t)
	uid := mustCreateActiveUser(t, svc, tid, "profile@example.com")

	if _, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "displayName", Value: "Renamed"},
	}); err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if pub.was(uid) {
		t.Fatal("profile-only PATCH must not publish a revocation")
	}
}

// TestDeactivationPublishFailurePropagates verifies a publish failure is
// surfaced (so the IdP retries) while the suspend remains durable.
func TestDeactivationPublishFailurePropagates(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Fail", Slug: "fail", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	users := memory.NewUserRepository(s)
	svc := NewSCIMService(users, memory.NewRoleRepository(s), memory.NewAuditLogRepository(s),
		WithRevocationPublisher(failingPublisher{}))

	created, err := svc.CreateUser(context.Background(), tn.ID, SCIMUser{UserName: "f@example.com", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)

	if _, err := svc.PatchUser(context.Background(), tn.ID, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	}); err == nil {
		t.Fatal("expected PatchUser to surface the publish failure")
	}
	// The suspend must still be durable despite the publish error.
	got, err := users.Get(context.Background(), tn.ID, uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status == repository.UserStatusActive {
		t.Error("user should remain suspended even though the revocation publish failed")
	}
}

// TestDeactivationNoRevokerIsNoop verifies the prior behaviour (no
// revoker wired) is preserved: deactivation simply suspends.
func TestDeactivationNoRevokerIsNoop(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	created, err := svc.CreateUser(context.Background(), tid, SCIMUser{UserName: "norev@example.com", Active: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid := uuidFromString(created.ID)
	patched, err := svc.PatchUser(context.Background(), tid, uid, []SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
	})
	if err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if patched.Active == nil || *patched.Active {
		t.Error("expected active=false after PATCH")
	}
}

// --- Fix 2: fully-qualified (URN-prefixed) filter attributes --------------

// TestListUsersFilterQualifiedAttribute verifies that Entra's
// fully-qualified attribute names resolve identically to their short
// form across the pushdown (eq/co/sw) and in-memory paths.
func TestListUsersFilterQualifiedAttribute(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)
	ctx := context.Background()
	seed := map[string]string{"alice@example.com": "Alice Smith", "bob@example.com": "Bob Jones"}
	for e, dn := range seed {
		if _, err := svc.CreateUser(ctx, tid, SCIMUser{UserName: e, DisplayName: dn}); err != nil {
			t.Fatalf("CreateUser(%s): %v", e, err)
		}
	}

	cases := []struct {
		name   string
		filter string
		want   int
	}{
		{"qualified userName eq", fmt.Sprintf(`%s:userName eq "alice@example.com"`, SCIMSchemaUser), 1},
		{"qualified userName sw", fmt.Sprintf(`%s:userName sw "alice"`, SCIMSchemaUser), 1},
		{"qualified userName co", fmt.Sprintf(`%s:userName co "example.com"`, SCIMSchemaUser), 2},
		{"qualified displayName co", fmt.Sprintf(`%s:displayName co "smith"`, SCIMSchemaUser), 1},
		{"short userName eq still works", `userName eq "bob@example.com"`, 1},
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
				t.Errorf("totalResults = %d, want %d for filter %q", list.TotalResults, tc.want, tc.filter)
			}
		})
	}
}

// --- Fix 3: duplicate bulkId within a request -----------------------------

// TestBulkDuplicateBulkIDRejected verifies a duplicate bulkId is
// rejected (RFC 7644 §3.7.2) rather than silently overwriting the prior
// mapping, while the first creation succeeds.
func TestBulkDuplicateBulkIDRejected(t *testing.T) {
	t.Parallel()
	svc, tid := newSCIMService(t)

	first, _ := json.Marshal(SCIMUser{UserName: "dup1@example.com", Active: boolPtr(true)})
	second, _ := json.Marshal(SCIMUser{UserName: "dup2@example.com", Active: boolPtr(true)})

	resp, err := svc.Bulk(context.Background(), tid, SCIMBulkRequest{
		Schemas: []string{SCIMSchemaBulkRequest},
		Operations: []SCIMBulkOperation{
			{Method: "POST", Path: "/Users", BulkID: "dup", Data: first},
			{Method: "POST", Path: "/Users", BulkID: "dup", Data: second},
		},
	})
	if err != nil {
		t.Fatalf("Bulk: %v", err)
	}
	if resp.Operations[0].Status != "201" {
		t.Errorf("first POST status = %s, want 201", resp.Operations[0].Status)
	}
	if resp.Operations[1].Status != "400" {
		t.Fatalf("duplicate bulkId status = %s, want 400 (%+v)", resp.Operations[1].Status, resp.Operations[1].Response)
	}
	if resp.Operations[1].Response == nil || resp.Operations[1].Response.ScimType != "invalidValue" {
		t.Errorf("duplicate bulkId scimType = %+v, want invalidValue", resp.Operations[1].Response)
	}
}

// --- SCIM filter grammar: table-driven valid + malformed inputs -----------

// TestParseFilterExprGrammar exercises the full RFC 7644 §3.4.2.2 filter
// grammar the list endpoints accept: every comparison operator, and/or
// precedence, parenthesisation, not(...), quoted strings with escapes,
// case-insensitive operators/keywords, plus a battery of malformed
// inputs that must be rejected (never panic).
func TestParseFilterExprGrammar(t *testing.T) {
	t.Parallel()
	valid := []string{
		`userName eq "alice"`,
		`userName ne "bob"`,
		`displayName co "smith"`,
		`userName sw "a"`,
		`userName ew "com"`,
		`emails pr`,
		`userName gt "a"`,
		`userName ge "a"`,
		`userName lt "z"`,
		`userName le "z"`,
		`userName EQ "alice"`,                    // case-insensitive op
		`userName eq "a" AND displayName co "b"`, // case-insensitive keyword
		`userName eq "a" or userName eq "b"`,     // or
		`userName eq "a" and displayName co "b" or active eq "true"`, // precedence: (a and b) or c
		`not (userName eq "a")`, // negation
		`not(userName eq "a")`,  // negation, no space
		`(userName eq "a" or userName eq "b") and active eq "true"`,  // grouping overrides precedence
		`userName eq "value with spaces and \"quotes\""`,             // escaped quotes
		`userName eq "back\\slash"`,                                  // escaped backslash
		`userName eq bareword`,                                       // unquoted value
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"`, // fully-qualified attr
	}
	for _, f := range valid {
		f := f
		t.Run("valid/"+f, func(t *testing.T) {
			t.Parallel()
			if _, err := parseFilterExpr(f); err != nil {
				t.Errorf("parseFilterExpr(%q) unexpected error: %v", f, err)
			}
		})
	}

	malformed := []string{
		``,                          // empty
		`   `,                       // whitespace only
		`userName`,                  // attr without operator
		`userName eq`,               // operator without value
		`userName xx "a"`,           // unknown operator
		`eq "a"`,                    // missing attribute
		`userName eq "unterminated`, // unterminated string
		`(userName eq "a"`,          // unbalanced open paren
		`userName eq "a")`,          // unbalanced close paren
		`not userName eq "a"`,       // not without parentheses
		`userName eq "a" and`,       // trailing operator
		`userName eq "a" "b"`,       // trailing token
		`userName[type eq "work"]`,  // valuePath unsupported
		`and userName eq "a"`,       // leading logical operator
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

// TestFilterPrecedenceEvaluation verifies and binds tighter than or, and
// that parentheses and not(...) change the result, by evaluating against
// concrete users rather than only asserting the parse succeeds.
func TestFilterPrecedenceEvaluation(t *testing.T) {
	t.Parallel()
	alice := SCIMUser{UserName: "alice@example.com", DisplayName: "Alice", Active: boolPtr(true)}
	bob := SCIMUser{UserName: "bob@example.com", DisplayName: "Bob", Active: boolPtr(false)}

	cases := []struct {
		name                 string
		filter               string
		matchAlice, matchBob bool
	}{
		{
			name:       "and tighter than or",
			filter:     `userName eq "bob@example.com" and active eq "true" or userName eq "alice@example.com"`,
			matchAlice: true,  // (bob and active) is false; or alice -> alice matches
			matchBob:   false, // bob is inactive, alice clause doesn't match bob
		},
		{
			name:       "parentheses override precedence",
			filter:     `(userName eq "bob@example.com" or userName eq "alice@example.com") and active eq "true"`,
			matchAlice: true,  // alice is active
			matchBob:   false, // bob is inactive
		},
		{
			name:       "not negates group",
			filter:     `not (active eq "true")`,
			matchAlice: false,
			matchBob:   true,
		},
		{
			name:       "presence operator",
			filter:     `displayName pr`,
			matchAlice: true,
			matchBob:   true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expr, err := parseFilterExpr(tc.filter)
			if err != nil {
				t.Fatalf("parseFilterExpr(%q): %v", tc.filter, err)
			}
			if got := expr.matchUser(alice); got != tc.matchAlice {
				t.Errorf("matchUser(alice) = %v, want %v", got, tc.matchAlice)
			}
			if got := expr.matchUser(bob); got != tc.matchBob {
				t.Errorf("matchUser(bob) = %v, want %v", got, tc.matchBob)
			}
		})
	}
}
