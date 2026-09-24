package regression_test

import (
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestMultilineAndNestedCases(t *testing.T) {
	fixtureDir, err := filepath.Abs("../fixtures/python")
	if err != nil {
		t.Fatalf("failed to resolve python fixtures dir: %v", err)
	}

	result, err := scanner.RunInternalScanner(fixtureDir)
	if err != nil {
		t.Fatalf("scanner failed: %v", err)
	}

	foundNestedOrMultiline := false
	for _, f := range result.Findings {
		if filepath.Base(f.File) == "multiline_nested.py" {
			foundNestedOrMultiline = true
			if f.ID != "VG-SAST-001" {
				t.Errorf("expected VG-SAST-001 for multiline_nested.py, got %s", f.ID)
			}
		}
	}

	if !foundNestedOrMultiline {
		t.Errorf("expected finding in multiline_nested.py")
	}
}

func TestDeterministicDeduplication(t *testing.T) {
	finding1 := scanner.Finding{
		ID:       "VG-SAST-001",
		RuleID:   "VG-SAST-001",
		Category: "sourcecode",
		Severity: "HIGH",
		Title:    "Potential SQL Injection",
		File:     "app/routes.py",
		Line:     42,
		Column:   1,
		Evidence: "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
	}

	finding2 := scanner.Finding{
		ID:       "VG-SAST-001",
		RuleID:   "VG-SAST-001",
		Category: "sourcecode",
		Severity: "HIGH",
		Title:    "Potential SQL Injection",
		File:     "app/routes.py",
		Line:     42,
		Column:   1,
		Evidence: "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
	}

	raw := []scanner.Finding{finding1, finding2}
	deduped := scanner.DeduplicateFindings(raw)

	if len(deduped) != 1 {
		t.Fatalf("expected exactly 1 deduplicated finding, got %d", len(deduped))
	}

	if deduped[0].Fingerprint == "" {
		t.Errorf("expected computed fingerprint on deduplicated finding")
	}
}
