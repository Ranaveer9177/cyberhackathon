package positive_test

import (
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestPositiveCasesDetection(t *testing.T) {
	fixtureDir, err := filepath.Abs("../fixtures")
	if err != nil {
		t.Fatalf("failed to resolve fixtures dir: %v", err)
	}

	result, err := scanner.RunInternalScanner(fixtureDir)
	if err != nil {
		t.Fatalf("scanner failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatalf("expected positive security findings in fixtures, got 0")
	}

	detectedRules := make(map[string]int)
	for _, f := range result.Findings {
		detectedRules[f.ID]++
		// Verify normalization
		if f.RuleID == "" {
			t.Errorf("Finding missing RuleID: %+v", f)
		}
		if f.Category == "" {
			t.Errorf("Finding missing Category: %+v", f)
		}
		if f.Severity == "" {
			t.Errorf("Finding missing Severity: %+v", f)
		}
		if f.Confidence == "" {
			t.Errorf("Finding missing Confidence: %+v", f)
		}
		if f.CWE == "" {
			t.Errorf("Finding missing CWE: %+v", f)
		}
		if f.Fingerprint == "" {
			t.Errorf("Finding missing Fingerprint: %+v", f)
		}
		if f.Column <= 0 {
			t.Errorf("Finding Column should be >= 1: %+v", f)
		}
	}

	expectedRules := []string{
		"VG-SAST-001", // SQL Injection
		"VG-SAST-002", // Command Injection
		"VG-SAST-003", // Eval
		"VG-SAST-004", // TLS
	}

	for _, ruleID := range expectedRules {
		if detectedRules[ruleID] == 0 {
			t.Errorf("expected positive detection for rule %s, but found 0 matches", ruleID)
		}
	}
}
