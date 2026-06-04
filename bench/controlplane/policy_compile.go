package main

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// PolicyCompileConfig parameterises the policy-compile bench. The
// compile path is pure CPU (no Postgres, no network), so this bench
// runs identically under --dry-run and against a real deployment — it
// never needs a live control plane.
type PolicyCompileConfig struct {
	// GraphSizes is the set of rule counts to measure a full compile
	// for.
	GraphSizes []int
	// PerTargetGraphSize is the rule count broken down per bundle
	// target.
	PerTargetGraphSize int
	// ConcurrencyLevels is the set of parallel-tenant fan-out levels.
	ConcurrencyLevels []int
	// Iterations is how many times each single-graph compile is
	// repeated; the reported CompileMs is the median, which is far
	// more stable than a single noisy sample.
	Iterations int
}

// DefaultPolicyCompileConfig is the full-fidelity configuration used
// for a real weekly run.
func DefaultPolicyCompileConfig() PolicyCompileConfig {
	return PolicyCompileConfig{
		GraphSizes:         []int{10, 100, 500, 1000},
		PerTargetGraphSize: 1000,
		ConcurrencyLevels:  []int{10, 100, 1000},
		Iterations:         25,
	}
}

// QuickPolicyCompileConfig is a reduced configuration for --dry-run /
// CI self-test: it keeps every graph size and target (so the report
// shape is identical) but trims iterations and the heaviest
// concurrency tier so the run finishes in well under a second.
func QuickPolicyCompileConfig() PolicyCompileConfig {
	return PolicyCompileConfig{
		GraphSizes:         []int{10, 100, 500, 1000},
		PerTargetGraphSize: 1000,
		ConcurrencyLevels:  []int{10, 100},
		Iterations:         5,
	}
}

// compileAllTargets runs the full compile pipeline for one parsed
// graph across every bundle target and returns the total emitted
// bundle size in bytes. It mirrors the control plane's compile path:
// per-target rule selection (Graph.CompileTarget), deterministic rule
// encoding (policy.EncodeRules), then MessagePack marshalling — the
// same wire format Service.Compile persists.
func compileAllTargets(g policy.Graph) (int, error) {
	var total int
	for _, target := range allBundleTargets {
		n, err := compileOneTarget(g, target)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// compileOneTarget compiles a parsed graph for a single bundle target
// and returns the encoded bundle size in bytes.
func compileOneTarget(g policy.Graph, target repository.PolicyBundleTarget) (int, error) {
	rules := g.CompileTarget(target)
	encoded, err := policy.EncodeRules(rules)
	if err != nil {
		return 0, fmt.Errorf("encode rules for %s: %w", target, err)
	}
	// Mirror the on-wire bundle: the control plane MessagePack-marshals
	// the per-target payload. We marshal the encoded rule document so
	// the byte count reflects the real bundle size, not the JSON
	// intermediate.
	wire, err := msgpack.Marshal(map[string]any{
		"t": string(target),
		"r": []byte(encoded),
	})
	if err != nil {
		return 0, fmt.Errorf("msgpack marshal bundle for %s: %w", target, err)
	}
	return len(wire), nil
}

// RunPolicyCompileBench measures policy-graph compilation across graph
// sizes, per bundle target, and under concurrent fan-out.
func RunPolicyCompileBench(cfg PolicyCompileConfig) (*PolicyCompileSection, error) {
	if cfg.Iterations <= 0 {
		cfg.Iterations = 1
	}
	section := &PolicyCompileSection{}

	for _, size := range cfg.GraphSizes {
		res, err := measureCompile(size, cfg.Iterations)
		if err != nil {
			return nil, err
		}
		section.PerGraphSize = append(section.PerGraphSize, res)
	}

	rawTarget, err := GenerateGraphJSON(cfg.PerTargetGraphSize)
	if err != nil {
		return nil, err
	}
	gTarget, err := policy.ParseGraph(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("parse per-target graph: %w", err)
	}
	for _, target := range allBundleTargets {
		durs := make([]time.Duration, 0, cfg.Iterations)
		var bundleBytes int
		for i := 0; i < cfg.Iterations; i++ {
			start := time.Now()
			n, err := compileOneTarget(gTarget, target)
			elapsed := time.Since(start)
			if err != nil {
				return nil, err
			}
			durs = append(durs, elapsed)
			bundleBytes = n
		}
		section.PerTarget = append(section.PerTarget, PolicyCompileResult{
			RuleCount:   cfg.PerTargetGraphSize,
			Target:      string(target),
			CompileMs:   medianMs(durs),
			BundleBytes: bundleBytes,
		})
	}

	for _, level := range cfg.ConcurrencyLevels {
		res, err := measureConcurrentCompile(level, cfg.PerTargetGraphSize)
		if err != nil {
			return nil, err
		}
		section.Concurrent = append(section.Concurrent, res)
	}

	return section, nil
}

// measureCompile runs `iterations` full all-target compiles of a
// freshly generated graph of the given size, returning the median
// compile time, the bundle size, and the mean heap bytes allocated
// per compile.
func measureCompile(size, iterations int) (PolicyCompileResult, error) {
	raw, err := GenerateGraphJSON(size)
	if err != nil {
		return PolicyCompileResult{}, err
	}

	durs := make([]time.Duration, 0, iterations)
	var bundleBytes int

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < iterations; i++ {
		// Parse is part of the compile cost the control plane pays on
		// every PUT /policy + compile, so it is inside the timed
		// region.
		start := time.Now()
		g, parseErr := policy.ParseGraph(raw)
		if parseErr != nil {
			return PolicyCompileResult{}, fmt.Errorf("parse %d-rule graph: %w", size, parseErr)
		}
		n, compileErr := compileAllTargets(g)
		elapsed := time.Since(start)
		if compileErr != nil {
			return PolicyCompileResult{}, compileErr
		}
		durs = append(durs, elapsed)
		bundleBytes = n
	}
	runtime.ReadMemStats(&after)

	allocPerCompile := (after.TotalAlloc - before.TotalAlloc) / uint64(iterations)
	return PolicyCompileResult{
		RuleCount:   size,
		Target:      "all",
		CompileMs:   medianMs(durs),
		BundleBytes: bundleBytes,
		AllocBytes:  allocPerCompile,
	}, nil
}

// measureConcurrentCompile compiles `tenants` graphs in parallel
// (each tenant gets its own parsed graph, as in production where every
// tenant compiles its own policy) and records the wall-clock time plus
// the per-compile latency distribution.
func measureConcurrentCompile(tenants, ruleCount int) (ConcurrentCompileResult, error) {
	raw, err := GenerateGraphJSON(ruleCount)
	if err != nil {
		return ConcurrentCompileResult{}, err
	}

	durs := make([]time.Duration, tenants)
	errs := make([]error, tenants)
	var wg sync.WaitGroup
	wallStart := time.Now()
	for i := 0; i < tenants; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			g, parseErr := policy.ParseGraph(raw)
			if parseErr != nil {
				errs[idx] = parseErr
				return
			}
			if _, cErr := compileAllTargets(g); cErr != nil {
				errs[idx] = cErr
				return
			}
			durs[idx] = time.Since(start)
		}(i)
	}
	wg.Wait()
	wall := time.Since(wallStart)

	for _, e := range errs {
		if e != nil {
			return ConcurrentCompileResult{}, fmt.Errorf("concurrent compile (%d tenants): %w", tenants, e)
		}
	}

	return ConcurrentCompileResult{
		Tenants:   tenants,
		RuleCount: ruleCount,
		WallMs:    float64(wall.Nanoseconds()) / 1e6,
		MeanMs:    meanMs(durs),
		P99Ms:     percentileMs(durs, 99),
	}, nil
}

// medianMs returns the median of the durations in milliseconds.
func medianMs(durs []time.Duration) float64 {
	if len(durs) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durs))
	copy(sorted, durs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return float64(sorted[mid].Nanoseconds()) / 1e6
	}
	return float64((sorted[mid-1] + sorted[mid]).Nanoseconds()) / 2e6
}

// meanMs returns the arithmetic mean of the durations in milliseconds.
func meanMs(durs []time.Duration) float64 {
	if len(durs) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durs {
		total += d
	}
	return float64(total.Nanoseconds()) / float64(len(durs)) / 1e6
}
