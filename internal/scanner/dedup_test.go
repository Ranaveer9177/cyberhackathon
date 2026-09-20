package scanner

import (
	"testing"
)

func TestDeduplicateFindings(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-001",
			Category:    "secret",
			Title:       "AWS Key",
			File:        "src/config.go",
			Line:        10,
			Evidence:    "MOCK_TOKEN_EVIDENCE_ABC",
		},
		{
			ID:          "VG-002",
			Category:    "secret",
			Title:       "AWS Key",
			File:        "src/config.go",
			Line:        10,
			Evidence:    "MOCK_TOKEN_EVIDENCE_ABC", // duplicate
		},
		{
			ID:          "VG-003",
			Category:    "sourcecode",
			Title:       "SQL Injection",
			File:        "src/db.go",
			Line:        45,
			Evidence:    "SELECT * FROM users WHERE id = " + "1",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(deduped))
	}

	if deduped[0].ID != "VG-001" {
		t.Errorf("expected first finding VG-001, got %s", deduped[0].ID)
	}
	if deduped[1].ID != "VG-003" {
		t.Errorf("expected second finding VG-003, got %s", deduped[1].ID)
	}
}
