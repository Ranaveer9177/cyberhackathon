package scanner

import (
	"path/filepath"
	"testing"
)

func TestInternalScannerOnTestProject(t *testing.T) {
	testProjDir, err := filepath.Abs("../../test-project")
	if err != nil {
		t.Fatalf("failed to resolve test-project path: %v", err)
	}

	result, err := RunInternalScanner(testProjDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Errorf("expected files to be scanned, got 0")
	}

	if len(result.Findings) == 0 {
		t.Errorf("expected findings in vulnerable test-project, got 0")
	}

	foundSecret := false
	foundSQL := false
	foundDocker := false

	for _, f := range result.Findings {
		if f.Category == "secret" {
			foundSecret = true
		}
		if f.Title == "SQL Injection" {
			foundSQL = true
		}
		if f.Category == "docker" {
			foundDocker = true
		}
	}

	if !foundSecret {
		t.Errorf("expected at least one secret finding in test-project")
	}
	if !foundSQL {
		t.Errorf("expected SQL injection finding in test-project")
	}
	if !foundDocker {
		t.Errorf("expected docker finding in test-project")
	}
}
