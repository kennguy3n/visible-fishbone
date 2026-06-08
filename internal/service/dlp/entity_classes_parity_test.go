package dlp

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// entityClassContractPath points at the cross-language source of truth
// for the NER entity-class wire names. The Rust enforcement plane is
// tested against the same file (crates/sng-dlp/tests/ml_classifier.rs),
// so the two implementations cannot drift silently.
const entityClassContractPath = "../../../crates/sng-dlp/assets/entity_classes.json"

// TestEntityClassesMatchSharedContract pins endpointEntityClasses (and
// the validEntityClassCSV accept/reject contract) to the shared
// entity-class file. If a class is added, removed, or renamed on the
// Go side without updating the contract — or the contract changes
// without the Go side following — this test fails. Its Rust twin
// guards the enforcement plane, so the previously manual Go/Rust sync
// is now enforced at test time on both sides.
func TestEntityClassesMatchSharedContract(t *testing.T) {
	raw, err := os.ReadFile(entityClassContractPath)
	if err != nil {
		t.Fatalf("read entity-class contract %s: %v", entityClassContractPath, err)
	}
	var contract struct {
		Classes []string `json:"classes"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("parse entity-class contract: %v", err)
	}
	if len(contract.Classes) == 0 {
		t.Fatal("entity-class contract lists no classes")
	}

	want := append([]string(nil), contract.Classes...)
	sort.Strings(want)

	got := make([]string, 0, len(endpointEntityClasses))
	for name := range endpointEntityClasses {
		got = append(got, name)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("entity-class set size mismatch: endpoint has %d %v, contract has %d %v",
			len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entity-class parity drift: endpoint=%v contract=%v", got, want)
		}
	}

	// Every contract class must pass CSV validation, and an unknown
	// name must be rejected — the same accept/reject contract the Rust
	// parse_entity_classes enforces.
	for _, name := range contract.Classes {
		if !validEntityClassCSV(name) {
			t.Errorf("validEntityClassCSV rejected contract class %q", name)
		}
	}
	if validEntityClassCSV("not_a_real_class") {
		t.Error("validEntityClassCSV accepted an unknown entity class")
	}
}
