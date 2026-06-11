package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// userRuleGraph builds a graph whose sole rule denies a user subject
// (matched by the supplied Match document) and otherwise allows. The
// rule rides the ZTNA domain over a flow event so no payload is needed.
func userRuleGraph(t *testing.T, match string) *GraphEvaluator {
	t.Helper()
	return &GraphEvaluator{graph: Graph{
		DefaultAction: VerbAllow,
		Rules: []Rule{{
			ID:     "deny-user",
			Domain: DomainZTNA,
			Verb:   VerbDeny,
			Subjects: []Subject{{
				Name:  "u",
				Kind:  SubjectKindUser,
				Match: json.RawMessage(match),
			}},
		}},
	}}
}

func flowEnv() schema.Envelope {
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		EventClass:    schema.EventClassFlow,
		Platform:      schema.PlatformLinux,
	}
}

func TestGraphEvaluator_UserSubject_MatchesResolvedPrincipal(t *testing.T) {
	t.Parallel()
	alice := uuid.New()
	bob := uuid.New()
	ev := userRuleGraph(t, `{"id":"`+alice.String()+`"}`)
	env := flowEnv()

	// The named user matches the principal -> the deny rule fires.
	v, err := ev.EvaluateWithPrincipal(context.Background(), env, &Principal{UserID: alice})
	if err != nil {
		t.Fatalf("evaluate(alice): %v", err)
	}
	if v != schema.VerdictDeny {
		t.Fatalf("alice should hit the user deny rule, got %q", v)
	}

	// A different principal does NOT match -> the rule is skipped and
	// the graph default (allow) governs. This is the correctness win:
	// the per-user rule no longer applies to everyone.
	v, err = ev.EvaluateWithPrincipal(context.Background(), env, &Principal{UserID: bob})
	if err != nil {
		t.Fatalf("evaluate(bob): %v", err)
	}
	if v != schema.VerdictAllow {
		t.Fatalf("bob should fall through to default allow, got %q", v)
	}
}

func TestGraphEvaluator_UserSubject_MatchesPrincipalRole(t *testing.T) {
	t.Parallel()
	role := uuid.New()
	other := uuid.New()
	ev := userRuleGraph(t, `{"ids":["`+role.String()+`"]}`)
	env := flowEnv()

	// Membership semantics: the user rule names a role/group id, and the
	// principal belongs to it -> match, even though the user's own id is
	// not named.
	v, err := ev.EvaluateWithPrincipal(context.Background(), env, &Principal{UserID: uuid.New(), RoleIDs: []uuid.UUID{role}})
	if err != nil {
		t.Fatalf("evaluate(member): %v", err)
	}
	if v != schema.VerdictDeny {
		t.Fatalf("a member of the named group should hit the rule, got %q", v)
	}

	// Not a member -> rule skipped -> default allow.
	v, err = ev.EvaluateWithPrincipal(context.Background(), env, &Principal{UserID: uuid.New(), RoleIDs: []uuid.UUID{other}})
	if err != nil {
		t.Fatalf("evaluate(non-member): %v", err)
	}
	if v != schema.VerdictAllow {
		t.Fatalf("a non-member should fall through to default allow, got %q", v)
	}
}

func TestGraphEvaluator_UserSubject_NoPrincipalUnderMatches(t *testing.T) {
	t.Parallel()
	// Without a principal (the data-plane simulator path), user identity
	// is unknown, so the user subject under-matches: the rule is treated
	// as applying. Evaluate (the principal-less entry point) must keep
	// this conservative behaviour so the simulator never under-reports.
	ev := userRuleGraph(t, `{"id":"`+uuid.New().String()+`"}`)
	v, err := ev.Evaluate(context.Background(), flowEnv())
	if err != nil {
		t.Fatalf("evaluate(no principal): %v", err)
	}
	if v != schema.VerdictDeny {
		t.Fatalf("user rule should under-match (apply) without a principal, got %q", v)
	}

	// A nil principal via EvaluateWithPrincipal is identical to Evaluate.
	v, err = ev.EvaluateWithPrincipal(context.Background(), flowEnv(), nil)
	if err != nil {
		t.Fatalf("evaluate(nil principal): %v", err)
	}
	if v != schema.VerdictDeny {
		t.Fatalf("nil principal should match Evaluate behaviour, got %q", v)
	}
}
