package complianceauto

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"
)

// EvidencePack is the on-demand, framework-mapped export of a tenant's
// compliance posture. It is a self-describing document an auditor can
// archive: every control carries its verdict, the evidence summary, the
// source subsystem, the observation time, and the structured evidence
// detail. It round-trips through JSON losslessly.
type EvidencePack struct {
	TenantID    uuid.UUID     `json:"tenant_id"`
	Framework   Framework     `json:"framework"`
	GeneratedAt time.Time     `json:"generated_at"`
	Summary     PackSummary   `json:"summary"`
	Controls    []PackControl `json:"controls"`
}

// PackSummary is the pass/fail/na tally for the pack's framework.
type PackSummary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
}

// PackControl is one control's evidence row in a pack.
type PackControl struct {
	ControlID   string          `json:"control_id"`
	Framework   Framework       `json:"framework"`
	Title       string          `json:"title"`
	Statement   string          `json:"statement"`
	Category    string          `json:"category"`
	CollectorID CollectorID     `json:"collector_id"`
	Status      Status          `json:"status"`
	Summary     string          `json:"summary"`
	Source      string          `json:"source"`
	ObservedAt  time.Time       `json:"observed_at"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
}

// BuildPack assembles an evidence pack for one framework from a tenant
// posture. The posture may already be filtered to the framework or carry
// every framework; only the requested framework's controls are included.
// It returns an error if the framework is not present in the posture.
func BuildPack(posture TenantPosture, framework Framework) (EvidencePack, error) {
	pack := EvidencePack{
		TenantID:    posture.TenantID,
		Framework:   framework,
		GeneratedAt: posture.GeneratedAt,
	}
	var found bool
	for _, fp := range posture.Frameworks {
		if fp.Framework != framework {
			continue
		}
		found = true
		pack.Summary = PackSummary{
			Total:         fp.Total,
			Pass:          fp.Pass,
			Fail:          fp.Fail,
			NotApplicable: fp.NotApplicable,
		}
		for _, c := range fp.Controls {
			pack.Controls = append(pack.Controls, PackControl{
				ControlID:   c.Control.ID,
				Framework:   c.Control.Framework,
				Title:       c.Control.Title,
				Statement:   c.Control.Statement,
				Category:    c.Control.Category,
				CollectorID: c.Control.CollectorID,
				Status:      c.Status,
				Summary:     c.Summary,
				Source:      c.Source,
				ObservedAt:  c.ObservedAt,
				Evidence:    c.Details,
			})
		}
	}
	if !found {
		return EvidencePack{}, fmt.Errorf("framework %q not present in posture", framework)
	}
	sort.SliceStable(pack.Controls, func(i, j int) bool {
		return pack.Controls[i].ControlID < pack.Controls[j].ControlID
	})
	return pack, nil
}

// MarshalJSON serializes the pack as indented JSON.
func (p EvidencePack) MarshalJSONIndent() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// WriteCSV writes the pack's controls as CSV. The header row names the
// columns; the evidence detail is embedded as a compact JSON string in
// the final column so the export stays a single flat table.
func (p EvidencePack) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	header := []string{
		"framework", "control_id", "title", "category", "status",
		"summary", "source", "observed_at", "evidence",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, c := range p.Controls {
		evidence := ""
		if len(c.Evidence) > 0 {
			evidence = string(c.Evidence)
		}
		record := []string{
			string(c.Framework),
			c.ControlID,
			c.Title,
			c.Category,
			string(c.Status),
			c.Summary,
			c.Source,
			c.ObservedAt.UTC().Format(time.RFC3339),
			evidence,
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ParsePackJSON deserializes a JSON-encoded pack, used by callers and
// round-trip tests.
func ParsePackJSON(b []byte) (EvidencePack, error) {
	var p EvidencePack
	if err := json.Unmarshal(b, &p); err != nil {
		return EvidencePack{}, err
	}
	return p, nil
}

// ScorePercent returns the pass rate over in-scope (non-NA) controls as
// an integer percentage in [0,100]; 100 when there are no in-scope
// controls. Useful for dashboards and the CSV/JSON summary.
func (s PackSummary) ScorePercent() int {
	inScope := s.Total - s.NotApplicable
	if inScope <= 0 {
		return 100
	}
	return int(float64(s.Pass) / float64(inScope) * 100)
}
