package residency

import (
	"errors"
	"testing"
)

func TestValidateRegion(t *testing.T) {
	t.Parallel()
	valid := []Region{"us-east", "ap-southeast-1", "a", "b", "eu-central-2", "ap-south"}
	for _, r := range valid {
		if err := ValidateRegion(r); err != nil {
			t.Errorf("ValidateRegion(%q) = %v, want nil", r, err)
		}
	}
	invalid := []Region{"", "   ", "-leading", "US East", "region!", "a..b", "/etc/passwd"}
	for _, r := range invalid {
		if err := ValidateRegion(r); !errors.Is(err, ErrInvalidRegion) {
			t.Errorf("ValidateRegion(%q) = %v, want ErrInvalidRegion", r, err)
		}
	}
}

func TestValidateRegionNormalizes(t *testing.T) {
	t.Parallel()
	if err := ValidateRegion("  AP-Southeast-1 "); err != nil {
		t.Errorf("whitespace/case should normalize and validate: %v", err)
	}
}

func TestRequireSupported(t *testing.T) {
	t.Parallel()
	j, err := RequireSupported("AP-Southeast-1")
	if err != nil {
		t.Fatalf("RequireSupported(ap-southeast-1) = %v", err)
	}
	if j.Country != "SG" {
		t.Errorf("country = %q, want SG", j.Country)
	}
	if len(j.Frameworks) == 0 {
		t.Error("expected frameworks for SG region")
	}
	// Syntactically valid but not catalogued.
	if _, err := RequireSupported("us-east"); !errors.Is(err, ErrUnsupportedRegion) {
		t.Errorf("us-east = %v, want ErrUnsupportedRegion", err)
	}
	// Malformed.
	if _, err := RequireSupported("not a region"); !errors.Is(err, ErrInvalidRegion) {
		t.Errorf("malformed = %v, want ErrInvalidRegion", err)
	}
}

func TestEnforceWrite(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		designated    Region
		target        Region
		wantViolation bool
	}{
		{"unconfigured allows any", "", "ap-southeast-1", false},
		{"unconfigured allows empty target", "", "", false},
		{"match allows", "ap-southeast-1", "ap-southeast-1", false},
		{"match normalizes", "AP-Southeast-1", "  ap-southeast-1 ", false},
		{"mismatch denies", "ap-southeast-1", "eu-central-1", true},
		{"unknown target denies fail-closed", "ap-southeast-1", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceWrite(tc.designated, tc.target, PlaneTelemetry)
			if tc.wantViolation {
				if !errors.Is(err, ErrResidencyViolation) {
					t.Fatalf("EnforceWrite(%q,%q) = %v, want ErrResidencyViolation", tc.designated, tc.target, err)
				}
				var v *Violation
				if !errors.As(err, &v) {
					t.Fatalf("error is not *Violation: %T", err)
				}
				if v.Plane != PlaneTelemetry {
					t.Errorf("violation plane = %q, want telemetry", v.Plane)
				}
			} else if err != nil {
				t.Fatalf("EnforceWrite(%q,%q) = %v, want nil", tc.designated, tc.target, err)
			}
		})
	}
}

func TestSupportedRegionsCovered(t *testing.T) {
	t.Parallel()
	regions := SupportedRegions()
	if len(regions) != len(catalog) {
		t.Fatalf("SupportedRegions returned %d, catalog has %d", len(regions), len(catalog))
	}
	for _, j := range regions {
		if j.Region == "" || j.Country == "" || len(j.Frameworks) == 0 {
			t.Errorf("incomplete jurisdiction: %+v", j)
		}
	}
}
