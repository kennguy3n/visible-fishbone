package complianceauto

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func samplePosture(t *testing.T) TenantPosture {
	t.Helper()
	at := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	details, _ := json.Marshal(map[string]any{"rls_enforced": true})
	return TenantPosture{
		TenantID:    uuid.New(),
		GeneratedAt: at,
		Frameworks: []FrameworkPosture{
			{
				Framework: FrameworkSOC2,
				Total:     2,
				Pass:      1,
				Fail:      1,
				Controls: []ControlResult{
					{
						Control:    Control{ID: "CC6.1", Framework: FrameworkSOC2, Title: "Default deny", Category: "Logical Access", CollectorID: CollectorPolicyDefaultDeny},
						Status:     StatusPass,
						Summary:    "ok",
						Source:     "policy_graph",
						ObservedAt: at,
						Details:    details,
					},
					{
						Control:    Control{ID: "CC6.7", Framework: FrameworkSOC2, Title: "Encryption at rest", Category: "Cryptography", CollectorID: CollectorEncryptionAtRest},
						Status:     StatusFail,
						Summary:    "no key-wrap master",
						Source:     "platform_config",
						ObservedAt: at,
					},
				},
			},
		},
	}
}

func TestBuildPack_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	pack, err := BuildPack(samplePosture(t), FrameworkSOC2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(pack.Controls) != 2 {
		t.Fatalf("controls = %d, want 2", len(pack.Controls))
	}
	// Controls are sorted by control id for stable exports.
	if pack.Controls[0].ControlID != "CC6.1" || pack.Controls[1].ControlID != "CC6.7" {
		t.Fatalf("controls not sorted: %s, %s", pack.Controls[0].ControlID, pack.Controls[1].ControlID)
	}

	raw, err := pack.MarshalJSONIndent()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back, err := ParsePackJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.Summary != pack.Summary {
		t.Fatalf("summary mismatch: %+v vs %+v", back.Summary, pack.Summary)
	}
	if !back.GeneratedAt.Equal(pack.GeneratedAt) {
		t.Fatalf("generated_at mismatch: %v vs %v", back.GeneratedAt, pack.GeneratedAt)
	}
}

func TestBuildPack_UnknownFramework(t *testing.T) {
	t.Parallel()
	if _, err := BuildPack(samplePosture(t), FrameworkISO27001); err == nil {
		t.Fatal("expected error for framework not present in posture")
	}
}

func TestEvidencePack_WriteCSV(t *testing.T) {
	t.Parallel()
	pack, err := BuildPack(samplePosture(t), FrameworkSOC2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := pack.WriteCSV(&buf); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	// Header + one row per control.
	if len(rows) != 3 {
		t.Fatalf("csv rows = %d, want 3", len(rows))
	}
	if rows[0][0] != "framework" || rows[0][1] != "control_id" {
		t.Fatalf("unexpected csv header: %v", rows[0])
	}
	if rows[1][1] != "CC6.1" || rows[1][4] != string(StatusPass) {
		t.Fatalf("unexpected first data row: %v", rows[1])
	}
}

func TestPackSummary_ScorePercent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   PackSummary
		want int
	}{
		{"all pass", PackSummary{Total: 4, Pass: 4}, 100},
		{"half", PackSummary{Total: 4, Pass: 2}, 50},
		{"na excluded from denominator", PackSummary{Total: 4, Pass: 2, NotApplicable: 2}, 100},
		{"all na", PackSummary{Total: 2, NotApplicable: 2}, 100},
		{"empty", PackSummary{}, 100},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.ScorePercent(); got != tc.want {
				t.Fatalf("ScorePercent() = %d, want %d", got, tc.want)
			}
		})
	}
}
