package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestReportGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_test_reports")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rep := &Report{
		ProjectName:  "TestApp",
		ScanTime:     "120ms",
		FilesScanned: 5,
		Findings: []scanner.Finding{
			{
				ID:             "VG-001",
				Category:       "secret",
				Severity:       "CRITICAL",
				Title:          "Hardcoded API Key",
				Description:    "Found exposed API key",
				File:           "config.go",
				Line:           10,
				Recommendation: "Revoke key",
				Confidence:     "HIGH",
			},
		},
		ScoreResult: risk.ScoreResult{
			Score:         85,
			Total:         100,
			CriticalCount: 1,
		},
		GateResult: gate.GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   "Critical security findings detected",
		},
		CategoryCounts: CategoryCounts{
			Secrets: 1,
		},
	}

	// Test JSON Report
	jsonPath := filepath.Join(tempDir, "scan.json")
	if err := WriteJSONReport(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Errorf("expected json report file to exist")
	}

	// Test HTML Report
	htmlPath := filepath.Join(tempDir, "scan.html")
	if err := WriteHTMLReport(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Errorf("expected html report file to exist")
	}
}
