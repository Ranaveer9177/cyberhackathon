package report

import (
	"encoding/json"
	"testing"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestGenerateSarif(t *testing.T) {
	r := &Report{
		ProjectName:  "TestProject",
		FilesScanned: 5,
		Findings: []scanner.Finding{
			{
				ID:          "VG-001",
				Category:    "secret",
				Severity:    "CRITICAL",
				Title:       "AWS Access Key",
				Description: "Hardcoded AWS Key detected",
				File:        "config.go",
				Line:        10,
			},
			{
				ID:          "VG-002",
				Category:    "sourcecode",
				Severity:    "MEDIUM",
				Title:       "Weak Crypto",
				Description: "Insecure cipher used",
				File:        "auth.go",
				Line:        25,
			},
		},
	}

	sarif := GenerateSarif(r)
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "VibeGuard" {
		t.Errorf("expected tool name VibeGuard, got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	if run.Results[0].Level != "error" {
		t.Errorf("expected critical finding to map to error level, got %s", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("expected medium finding to map to warning level, got %s", run.Results[1].Level)
	}

	// Verify valid JSON
	bytes, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("failed to marshal SARIF to JSON: %v", err)
	}
	if len(bytes) == 0 {
		t.Fatal("empty SARIF JSON output")
	}
}
