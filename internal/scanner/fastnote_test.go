package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFastNoteBenchmarkDetection(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../tests/fixtures/fastnote")
	if err != nil {
		t.Fatalf("failed to resolve fixture directory: %v", err)
	}

	result, err := RunInternalScanner(fixtureDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Fatalf("expected files to be scanned in FastNote fixtures, got 0")
	}

	rulesHit := make(map[string]bool)
	for _, f := range result.Findings {
		rulesHit[f.ID] = true
	}

	expectedRules := []string{
		"VG-SAST-001", // SQL Injection
		"VG-SAST-002", // Command Injection
		"VG-AUTH-001", // Weak Password Hashing
		"VG-AUTH-002", // Predictable Token
		"VG-WEBHOOK-001", // Webhook signature missing
	}

	for _, ruleID := range expectedRules {
		if !rulesHit[ruleID] {
			t.Errorf("expected rule %s to trigger on FastNote fixtures, but was not found. Findings: %+v", ruleID, result.Findings)
		}
	}

	// Verify Bearer / Token finding was caught
	foundAuth := false
	for _, f := range result.Findings {
		if f.ID == "VG-AUTH-003" || f.ID == "VG-SEC-008" || strings.Contains(strings.ToLower(f.Title), "bearer") || strings.Contains(strings.ToLower(f.Title), "token") {
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		t.Errorf("expected hardcoded token/bearer finding in hardcoded_auth.py")
	}

	// Verify Docker compose findings were caught
	foundDockerCompose := false
	for _, f := range result.Findings {
		if strings.HasPrefix(f.ID, "VG-DCK-") {
			foundDockerCompose = true
			break
		}
	}
	if !foundDockerCompose {
		t.Errorf("expected Docker Compose findings in docker-compose.yml")
	}
}
