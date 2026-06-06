// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package region

import "testing"

func TestGroupFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want Group
		ok   bool
	}{
		{"SEA", GroupSEA, true},
		{"sea", GroupSEA, true},
		{" Sg ", GroupSEA, true},
		{"singapore", GroupSEA, true},
		{"jakarta", GroupSEA, true},
		{"ap-southeast-1", GroupSEA, true},
		{"GCC", GroupGCC, true},
		{"dubai", GroupGCC, true},
		{"riyadh", GroupGCC, true},
		{"bahrain", GroupGCC, true},
		{"me-south-1", GroupGCC, true},
		{"DACH", GroupDACH, true},
		{"zurich", GroupDACH, true},
		{"frankfurt", GroupDACH, true},
		{"eu-central-1", GroupDACH, true},
		{"eu-west-1", GroupDACH, true},
		{"", "", false},
		{"   ", "", false},
		{"antarctica", "", false},
		{"us-east-1", "", false},
	}
	for _, c := range cases {
		got, ok := GroupFor(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("GroupFor(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestGroupValid(t *testing.T) {
	t.Parallel()
	for _, g := range []Group{GroupSEA, GroupGCC, GroupDACH} {
		if !g.Valid() {
			t.Errorf("%q should be valid", g)
		}
	}
	for _, g := range []Group{"", "sea", "APAC", "us"} {
		if g.Valid() {
			t.Errorf("%q should be invalid", g)
		}
	}
}
