package main

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func TestGenerateGraphJSONValidAndSized(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 10, 100, 250} {
		raw, err := GenerateGraphJSON(size)
		if err != nil {
			t.Fatalf("GenerateGraphJSON(%d): %v", size, err)
		}
		g, err := policy.ParseGraph(raw)
		if err != nil {
			t.Fatalf("ParseGraph(%d-rule graph): %v", size, err)
		}
		if len(g.Rules) != size {
			t.Fatalf("graph has %d rules, want %d", len(g.Rules), size)
		}
	}
}

func TestGenerateGraphJSONNegative(t *testing.T) {
	t.Parallel()
	if _, err := GenerateGraphJSON(-1); err == nil {
		t.Fatal("expected error for negative rule count")
	}
}

func TestGenerateGraphDeterministic(t *testing.T) {
	t.Parallel()
	a, err := GenerateGraphJSON(100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateGraphJSON(100)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("graph generation is not deterministic for a fixed rule count")
	}
}

func TestCompileTargetsRouteByDomain(t *testing.T) {
	t.Parallel()
	// A graph spanning every domain must route a non-empty rule set
	// to the edge bundle and a (smaller) set to the mobile bundle,
	// proving CompileTarget is doing real per-target selection.
	raw, err := GenerateGraphJSON(70) // 10 of each of 7 domains
	if err != nil {
		t.Fatal(err)
	}
	g, err := policy.ParseGraph(raw)
	if err != nil {
		t.Fatal(err)
	}
	edge := len(g.CompileTarget(repository.PolicyBundleTargetEdge))
	mobile := len(g.CompileTarget(repository.PolicyBundleTargetMobile))
	if edge == 0 {
		t.Fatal("edge bundle unexpectedly empty")
	}
	if mobile >= edge {
		t.Fatalf("mobile bundle (%d rules) should be a strict subset of edge (%d rules)", mobile, edge)
	}
}

func TestRunPolicyCompileBenchQuick(t *testing.T) {
	t.Parallel()
	section, err := RunPolicyCompileBench(QuickPolicyCompileConfig())
	if err != nil {
		t.Fatalf("RunPolicyCompileBench: %v", err)
	}
	if len(section.PerGraphSize) != 4 {
		t.Fatalf("PerGraphSize has %d entries, want 4", len(section.PerGraphSize))
	}
	for _, r := range section.PerGraphSize {
		if r.CompileMs <= 0 {
			t.Errorf("%d-rule compile reported non-positive time %v", r.RuleCount, r.CompileMs)
		}
		if r.BundleBytes <= 0 {
			t.Errorf("%d-rule compile reported non-positive bundle size %d", r.RuleCount, r.BundleBytes)
		}
	}
	if len(section.PerTarget) != 4 {
		t.Fatalf("PerTarget has %d entries, want 4 (one per bundle target)", len(section.PerTarget))
	}
	if len(section.Concurrent) != 2 {
		t.Fatalf("Concurrent has %d entries, want 2", len(section.Concurrent))
	}
}
