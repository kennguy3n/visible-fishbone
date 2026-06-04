package main

import (
	"encoding/json"
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// graphDomains is the rotation of enforcement domains the generated
// graphs spread rules across, so CompileTarget exercises real
// per-target routing (an all-NGFW graph would never populate the
// mobile/cloud bundles).
var graphDomains = []policy.Domain{
	policy.DomainNGFW,
	policy.DomainSWG,
	policy.DomainDNS,
	policy.DomainZTNA,
	policy.DomainSDWAN,
	policy.DomainDLP,
	policy.DomainInlineCASB,
}

// graphVerbs is the rotation of policy verbs applied to generated
// rules.
var graphVerbs = []policy.Verb{
	policy.VerbAllow,
	policy.VerbInspect,
	policy.VerbSteer,
	policy.VerbDecrypt,
	policy.VerbLog,
	policy.VerbDeny,
}

// GenerateGraphJSON builds a deterministic, schema-valid policy graph
// document with exactly ruleCount rules, spread across every
// enforcement domain and verb. The output is the JSON shape the
// control-plane PUT /policy endpoint accepts and that policy.ParseGraph
// decodes — so the same bytes drive both the in-process compile bench
// and the live api-latency heavy-write workload.
//
// Each rule carries an inline subject + predicate plus a reference to a
// shared named subject, so the compiler's vertex-resolution and
// per-target selection both do real work. The graph is deterministic
// for a given ruleCount (no randomness) so two runs compile identical
// input and bundle bytes are comparable.
func GenerateGraphJSON(ruleCount int) (json.RawMessage, error) {
	if ruleCount < 0 {
		return nil, fmt.Errorf("rule count must be non-negative, got %d", ruleCount)
	}

	// A small set of named subjects/predicates the rules reference,
	// exercising the ref-resolution path in Validate/CompileTarget.
	subjects := []policy.Subject{
		{Name: "corp-users", Kind: policy.SubjectKindUser, Match: json.RawMessage(`{"group":"employees"}`)},
		{Name: "managed-devices", Kind: policy.SubjectKindDevice, Match: json.RawMessage(`{"posture":"compliant"}`)},
		{Name: "branch-sites", Kind: policy.SubjectKindSite, Match: json.RawMessage(`{"region":"emea"}`)},
	}
	predicates := []policy.Predicate{
		{Name: "business-hours", Match: json.RawMessage(`{"time_of_day":"weekday"}`)},
		{Name: "geo-eu", Match: json.RawMessage(`{"geo":"EU"}`)},
	}

	rules := make([]policy.Rule, 0, ruleCount)
	for i := 0; i < ruleCount; i++ {
		domain := graphDomains[i%len(graphDomains)]
		verb := graphVerbs[i%len(graphVerbs)]
		subjRef := subjects[i%len(subjects)].Name
		predRef := predicates[i%len(predicates)].Name
		rules = append(rules, policy.Rule{
			ID:            fmt.Sprintf("rule-%05d", i),
			Domain:        domain,
			Verb:          verb,
			SubjectRefs:   []string{subjRef},
			PredicateRefs: []string{predRef},
			Subjects: []policy.Subject{
				{Name: fmt.Sprintf("inline-net-%05d", i), Kind: policy.SubjectKindNetwork,
					Match: json.RawMessage(fmt.Sprintf(`{"cidr":"10.%d.%d.0/24"}`, i%256, (i/256)%256))},
			},
			Predicates: []policy.Predicate{
				{Name: fmt.Sprintf("inline-cat-%05d", i),
					Match: json.RawMessage(fmt.Sprintf(`{"category":"cat-%d"}`, i%64))},
			},
			Description: fmt.Sprintf("synthetic bench rule %d (%s/%s)", i, domain, verb),
		})
	}

	g := policy.Graph{
		Version:       1,
		DefaultAction: policy.VerbDeny,
		Subjects:      subjects,
		Predicates:    predicates,
		Rules:         rules,
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("marshal generated graph: %w", err)
	}
	// Parse-validate eagerly so a generator bug surfaces here rather
	// than as a confusing mid-bench compile error.
	if _, err := policy.ParseGraph(raw); err != nil {
		return nil, fmt.Errorf("generated graph failed validation: %w", err)
	}
	return raw, nil
}

// allBundleTargets is the stable ordering of compile targets the
// per-target bench iterates.
var allBundleTargets = []repository.PolicyBundleTarget{
	repository.PolicyBundleTargetEdge,
	repository.PolicyBundleTargetEndpoint,
	repository.PolicyBundleTargetCloud,
	repository.PolicyBundleTargetMobile,
}
