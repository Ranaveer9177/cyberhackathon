package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestBaselineSuppression(t *testing.T) {
	futureDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	pastDate := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")

	findings := []scanner.Finding{
		{
			ID:    "VG-001",
			Title: "Hardcoded Secret",
			File:  "src/config.go",
			Line:  12,
		},
		{
			ID:    "VG-002",
			Title: "Weak Crypto",
			File:  "src/auth.go",
			Line:  40,
		},
		{
			ID:    "VG-003",
			Title: "SQL Injection",
			File:  "src/db.go",
			Line:  55,
		},
	}

	suppressions := []Suppression{
		{
			RuleID:  "VG-001",
			File:    "src/config.go",
			Line:    12,
			Reason:  "Approved mock fixture for local tests",
			Expires: futureDate,
		},
		{
			RuleID:  "VG-002",
			File:    "src/auth.go",
			Line:    40,
			Reason:  "Legacy crypto will be refactored next sprint",
			Expires: pastDate, // Expired!
		},
	}

	active, suppressedCount := FilterSuppressedFindings(findings, suppressions)

	if suppressedCount != 1 {
		t.Errorf("expected 1 suppressed finding, got %d", suppressedCount)
	}

	if len(active) != 2 {
		t.Fatalf("expected 2 active findings, got %d", len(active))
	}

	// VG-001 must be suppressed, VG-002 (expired) and VG-003 must be active
	for _, a := range active {
		if a.ID == "VG-001" {
			t.Errorf("VG-001 should have been suppressed!")
		}
	}
}

func TestLoadBaseline_ValidFormats(t *testing.T) {
	tmpDir := t.TempDir()
	vgDir := filepath.Join(tmpDir, ".vibeguard")
	_ = os.MkdirAll(vgDir, 0755)

	// Format 1: Array of suppressions
	arrayJSON := `[
		{"rule_id": "VG-001", "file": "src/config.go", "reason": "Test reason", "expires": "2027-01-01"}
	]`
	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(arrayJSON), 0644)

	list, err := LoadBaseline(tmpDir)
	if err != nil {
		t.Fatalf("LoadBaseline array format failed: %v", err)
	}
	if len(list) != 1 || list[0].RuleID != "VG-001" {
		t.Errorf("unexpected loaded baseline: %+v", list)
	}

	// Format 2: Object with "suppressions"
	objJSON := `{
		"suppressions": [
			{"rule_id": "VG-002", "file": "src/auth.go", "reason": "Obj reason"}
		]
	}`
	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(objJSON), 0644)

	list2, err := LoadBaseline(tmpDir)
	if err != nil {
		t.Fatalf("LoadBaseline object format failed: %v", err)
	}
	if len(list2) != 1 || list2[0].RuleID != "VG-002" {
		t.Errorf("unexpected loaded baseline: %+v", list2)
	}
}

func TestLoadBaseline_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	vgDir := filepath.Join(tmpDir, ".vibeguard")
	_ = os.MkdirAll(vgDir, 0755)

	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(`{ "suppressions": [invalid json`), 0644)

	_, err := LoadBaseline(tmpDir)
	if err == nil {
		t.Fatal("expected error on malformed baseline JSON, got nil")
	}
	if !strings.Contains(err.Error(), "malformed baseline file") {
		t.Errorf("expected 'malformed baseline file' in error message, got: %v", err)
	}
}

func TestLoadBaseline_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	vgDir := filepath.Join(tmpDir, ".vibeguard")
	_ = os.MkdirAll(vgDir, 0755)

	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(`   `), 0644)

	_, err := LoadBaseline(tmpDir)
	if err == nil {
		t.Fatal("expected error on empty baseline file, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error message, got: %v", err)
	}
}

func TestLoadBaseline_InvalidDate(t *testing.T) {
	tmpDir := t.TempDir()
	vgDir := filepath.Join(tmpDir, ".vibeguard")
	_ = os.MkdirAll(vgDir, 0755)

	invalidDateJSON := `[
		{"rule_id": "VG-001", "file": "src/config.go", "reason": "Test", "expires": "31-12-2026"}
	]`
	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(invalidDateJSON), 0644)

	_, err := LoadBaseline(tmpDir)
	if err == nil {
		t.Fatal("expected error on invalid date format, got nil")
	}
	if !strings.Contains(err.Error(), "invalid expiration format") {
		t.Errorf("expected 'invalid expiration format' in error, got: %v", err)
	}
}

func TestLoadBaseline_MissingRuleAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	vgDir := filepath.Join(tmpDir, ".vibeguard")
	_ = os.MkdirAll(vgDir, 0755)

	emptyEntryJSON := `[
		{"reason": "Only reason without rule_id or file"}
	]`
	_ = os.WriteFile(filepath.Join(vgDir, "baseline.json"), []byte(emptyEntryJSON), 0644)

	_, err := LoadBaseline(tmpDir)
	if err == nil {
		t.Fatal("expected error when rule_id and file are both empty, got nil")
	}
	if !strings.Contains(err.Error(), "must specify rule_id or file") {
		t.Errorf("expected 'must specify rule_id or file' in error, got: %v", err)
	}
}

func TestLoadBaseline_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	list, err := LoadBaseline(tmpDir)
	if err != nil {
		t.Fatalf("expected nil error when baseline.json does not exist, got: %v", err)
	}
	if list != nil {
		t.Errorf("expected nil list, got %+v", list)
	}
}
