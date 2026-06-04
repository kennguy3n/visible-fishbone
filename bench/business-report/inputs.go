package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Static inputs: theoretical targets and competitor datasheet numbers.
// ---------------------------------------------------------------------------

// Theoretical mirrors bench/business-report/theoretical.json.
type Theoretical struct {
	EdgeThroughput []EdgeTarget       `json:"edge_throughput"`
	ControlPlane   ControlPlaneTarget `json:"control_plane"`
	PolicyEval     PolicyEvalTarget   `json:"policy_eval"`
	Telemetry      map[string]any     `json:"telemetry"`
	UnitEconomics  UnitEconomics      `json:"unit_economics"`
}

// EdgeTarget is a per-SKU design target for the edge data path.
type EdgeTarget struct {
	SKU        string  `json:"sku"`
	VCPUs      int     `json:"vcpus"`
	RAMGB      int     `json:"ram_gb"`
	NICGbps    float64 `json:"nic_gbps"`
	TargetGbps float64 `json:"target_gbps"`
	Note       string  `json:"note,omitempty"`
}

// ControlPlaneTarget holds the control-plane design targets.
type ControlPlaneTarget struct {
	APIP99MsAt5kTenants      float64 `json:"api_p99_ms_at_5k_tenants"`
	PolicyCompile100RulesMs  float64 `json:"policy_compile_100_rules_ms"`
	PolicyCompile1000RulesMs float64 `json:"policy_compile_1000_rules_ms"`
}

// PolicyEvalTarget holds the policy-eval design target.
type PolicyEvalTarget struct {
	Target   string   `json:"target"`
	TargetNs float64  `json:"target_ns"`
	Shapes   []string `json:"shapes"`
}

// UnitEconomics holds the per-cohort cost envelope.
type UnitEconomics struct {
	Source          string         `json:"_source"`
	Starter         Cohort         `json:"starter"`
	Growth          Cohort         `json:"growth"`
	Scale           Cohort         `json:"scale"`
	OverallEnvelope []float64      `json:"overall_envelope_user_month"`
	Extra           map[string]any `json:"-"`
}

// Cohort is one pricing cohort's direct-infra envelope.
type Cohort struct {
	InfraCostUserMonth []float64 `json:"infra_cost_user_month"`
	SiteMonth          []float64 `json:"site_month"`
	DataGuardUserMonth []float64 `json:"data_guard_user_month,omitempty"`
}

func loadTheoretical(path string) (*Theoretical, error) {
	var t Theoretical
	if err := readJSON(path, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Competitors mirrors bench/business-report/competitors.json.
type Competitors struct {
	Vendors      []Vendor             `json:"vendors"`
	ControlPlane []CompetitorCPMetric `json:"control_plane"`
}

// Vendor is one competitor appliance/cloud product.
type Vendor struct {
	Vendor  string             `json:"vendor"`
	Model   string             `json:"model"`
	Cores   *int               `json:"cores"`
	Metrics []CompetitorMetric `json:"metrics"`
}

// CompetitorMetric is a single published datasheet figure.
type CompetitorMetric struct {
	Metric           string  `json:"metric"`
	Value            float64 `json:"value"`
	Unit             string  `json:"unit"`
	MapsToInspection string  `json:"maps_to_inspection"`
	SourceURL        string  `json:"source_url"`
	Caveat           string  `json:"caveat"`
}

// CompetitorCPMetric is a published control-plane figure (a range).
type CompetitorCPMetric struct {
	Vendor       string    `json:"vendor"`
	Product      string    `json:"product"`
	Metric       string    `json:"metric"`
	ValueRangeMs []float64 `json:"value_range_ms"`
	AtScale      string    `json:"at_scale,omitempty"`
	Caveat       string    `json:"caveat"`
}

func loadCompetitors(path string) (*Competitors, error) {
	var c Competitors
	if err := readJSON(path, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// Session 1 — control-plane scale bench report.json
// ---------------------------------------------------------------------------

// ControlPlaneReport is the subset of bench/controlplane's BusinessBenchmarkReport
// that this tool consumes.
type ControlPlaneReport struct {
	SchemaVersion int                  `json:"schema_version"`
	UnixTimeSecs  int64                `json:"unix_time_secs"`
	DryRun        bool                 `json:"dry_run"`
	APILatency    *cpAPILatencySection `json:"api_latency"`
	PolicyCompile *cpPolicyCompile     `json:"policy_compile"`
	PostgresScale *cpPostgresScale     `json:"postgres_scale"`
	Theoretical   cpTheoretical        `json:"theoretical"`
	Competitor    cpCompetitor         `json:"competitor"`
	Verdicts      []cpVerdict          `json:"verdicts"`
}

type cpAPILatencySection struct {
	Tiers []cpAPITier `json:"tiers"`
}

type cpAPITier struct {
	TenantCount           int     `json:"tenant_count"`
	OverallP99Ms          float64 `json:"overall_p99_ms"`
	OverallRequestsPerSec float64 `json:"overall_requests_per_sec"`
	ErrorRate             float64 `json:"error_rate"`
}

type cpPolicyCompile struct {
	PerGraphSize []cpCompileResult `json:"per_graph_size"`
}

type cpCompileResult struct {
	RuleCount int     `json:"rule_count"`
	Target    string  `json:"target"`
	CompileMs float64 `json:"compile_ms"`
}

type cpPostgresScale struct {
	TenantCount int `json:"tenant_count"`
	RLS         struct {
		OverheadPct float64 `json:"overhead_pct"`
	} `json:"rls"`
}

type cpTheoretical struct {
	APIP99Ms                float64 `json:"api_p99_ms"`
	PolicyCompile100RuleMs  float64 `json:"policy_compile_100_rule_ms"`
	PolicyCompile1000RuleMs float64 `json:"policy_compile_1000_rule_ms"`
}

type cpCompetitor struct {
	FortinetPolicyPushP99Ms    float64 `json:"fortinet_policy_push_p99_ms"`
	ZscalerTenantCRUDP99Ms     float64 `json:"zscaler_tenant_crud_p99_ms"`
	PaloAltoPolicyCompileP99Ms float64 `json:"palo_alto_policy_compile_p99_ms"`
	Caveat                     string  `json:"caveat"`
}

type cpVerdict struct {
	Metric string `json:"metric"`
	Status string `json:"status"`
	Gap    string `json:"gap"`
}

func loadControlPlane(path string) (*ControlPlaneReport, error) {
	var r ControlPlaneReport
	if err := readJSON(path, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// Session 2 — telemetry pipeline report(s)
// ---------------------------------------------------------------------------

// TelemetryReport is the generic section/metric report emitted by bench/telemetry.
type TelemetryReport struct {
	SchemaVersion int                `json:"schema_version"`
	Benchmark     string             `json:"benchmark"`
	UnixTimeSecs  int64              `json:"unix_time_secs"`
	DryRun        bool               `json:"dry_run"`
	Sections      []TelemetrySection `json:"sections"`
	Caveats       []string           `json:"caveats"`
}

type TelemetrySection struct {
	Title   string            `json:"title"`
	Summary string            `json:"summary,omitempty"`
	Metrics []TelemetryMetric `json:"metrics"`
}

type TelemetryMetric struct {
	Name        string   `json:"name"`
	Unit        string   `json:"unit,omitempty"`
	Actual      float64  `json:"actual"`
	Theoretical *float64 `json:"theoretical,omitempty"`
	Competitor  *float64 `json:"competitor,omitempty"`
	Verdict     string   `json:"verdict"`
	Note        string   `json:"note,omitempty"`
}

// loadTelemetry accepts a comma-separated list of files, or a single directory
// (in which case every *.json inside it is loaded). Reports are sorted by
// benchmark name for stable output.
func loadTelemetry(spec string) ([]*TelemetryReport, error) {
	var paths []string
	info, statErr := os.Stat(spec)
	switch {
	case statErr == nil && info.IsDir():
		entries, err := os.ReadDir(spec)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				paths = append(paths, filepath.Join(spec, e.Name()))
			}
		}
	case statErr != nil && !strings.Contains(spec, ",") && !errors.Is(statErr, os.ErrNotExist):
		// A single concrete path that exists but cannot be stat'd (e.g.
		// permission denied) is a real error, not a comma-separated list.
		return nil, statErr
	default:
		for _, p := range strings.Split(spec, ",") {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no telemetry report files found for %q", spec)
	}

	var reports []*TelemetryReport
	for _, p := range paths {
		var r TelemetryReport
		if err := readJSON(p, &r); err != nil {
			return nil, err
		}
		reports = append(reports, &r)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Benchmark < reports[j].Benchmark })
	return reports, nil
}

// ---------------------------------------------------------------------------
// Session 3 — Rust edge business-report .json
// ---------------------------------------------------------------------------

// EdgeReport mirrors bench/src/business_report.rs's serialized shape.
type EdgeReport struct {
	GeneratedUnixSecs int64     `json:"generated_unix_secs"`
	SKUs              []EdgeSKU `json:"skus"`
}

type EdgeSKU struct {
	Profile EdgeProfile      `json:"profile"`
	Reports []EdgeModeReport `json:"reports"`
}

type EdgeProfile struct {
	Name       string  `json:"name"`
	VCPUs      int     `json:"vcpus"`
	RAMGB      int     `json:"ram_gb"`
	NICGbps    float64 `json:"nic_gbps"`
	TargetGbps float64 `json:"target_gbps"`
}

type EdgeModeReport struct {
	Mode                 string             `json:"mode"`
	Dimensions           EdgeDimensions     `json:"dimensions"`
	Throughput           *EdgeThroughputAgg `json:"throughput,omitempty"`
	TargetGbps           float64            `json:"target_gbps"`
	CompetitorComparison *EdgeCompetitorCmp `json:"competitor_comparison,omitempty"`
}

type EdgeDimensions struct {
	PacketSize  int    `json:"packet_size"`
	PolicyRules int    `json:"policy_rules"`
	Inspection  string `json:"inspection"`
}

type EdgeThroughputAgg struct {
	MaxPps   float64 `json:"max_pps"`
	MaxGbps  float64 `json:"max_gbps"`
	MeanGbps float64 `json:"mean_gbps"`
}

type EdgeCompetitorCmp struct {
	SngMeasuredGbps float64             `json:"sng_measured_gbps"`
	Feature         string              `json:"feature"`
	Rows            []EdgeCompetitorRow `json:"rows"`
}

type EdgeCompetitorRow struct {
	Competitor    string  `json:"competitor"`
	PublishedGbps float64 `json:"published_gbps"`
	DeltaPct      float64 `json:"delta_pct"`
	Verdict       string  `json:"verdict"`
}

func loadEdge(path string) (*EdgeReport, error) {
	var r EdgeReport
	if err := readJSON(path, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// readJSON decodes a JSON file, disallowing unknown root corruption while
// tolerating extra fields the upstream tools may add.
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
