package database

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"4.17.20", "4.17.21", -1},
		{"2.0.1", "2.2.5", -1},
		{"v0.3.7", "v0.3.8", -1},
		{"v0.0.0-20220314234659-1baeb1ce4c0b", "v0.0.0-20220412211245-5be80e882529", -1},
	}

	for _, tt := range tests {
		res := CompareVersions(tt.v1, tt.v2)
		if res != tt.expected {
			t.Errorf("CompareVersions(%q, %q) = %d, expected %d", tt.v1, tt.v2, res, tt.expected)
		}
	}
}

func TestMatchConstraint(t *testing.T) {
	tests := []struct {
		ver        string
		constraint string
		expected   bool
	}{
		{"4.17.20", "< 4.17.21", true},
		{"4.17.21", "< 4.17.21", false},
		{"4.17.22", "< 4.17.21", false},
		{"2.0.1", "<= 2.0.1", true},
		{"2.0.2", "<= 2.0.1", false},
		{"1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"2.5.0", ">= 1.0.0, < 2.0.0", false},
	}

	for _, tt := range tests {
		res := MatchConstraint(tt.ver, tt.constraint)
		if res != tt.expected {
			t.Errorf("MatchConstraint(%q, %q) = %v, expected %v", tt.ver, tt.constraint, res, tt.expected)
		}
	}
}

func TestIsVulnerable(t *testing.T) {
	rec := VulnerabilityRecord{
		ID:               "TEST-001",
		Package:          "test-pkg",
		Ecosystem:        "npm",
		AffectedVersions: []string{"< 2.0.0"},
		FixedVersions:    []string{"2.0.0"},
		Ranges: []RangeSpec{
			{
				Type: "SEMVER",
				Events: []EventSpec{
					{Introduced: "1.0.0", Fixed: "2.0.0"},
				},
			},
		},
	}

	if !rec.IsVulnerable("1.5.0") {
		t.Errorf("expected 1.5.0 to be vulnerable")
	}
	if rec.IsVulnerable("2.0.0") {
		t.Errorf("expected 2.0.0 to NOT be vulnerable")
	}
	if rec.IsVulnerable("2.1.0") {
		t.Errorf("expected 2.1.0 to NOT be vulnerable")
	}
}
