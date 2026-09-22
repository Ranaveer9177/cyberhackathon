package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInternalScannerOnEphemeralProject(t *testing.T) {
	tempDir := t.TempDir()

	mockAWS := string([]byte{'A', 'K', 'I', 'A'}) + "IOSFODNN7EXAMPLE"

	// 1. Ephemeral Secret File (.env)
	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte(mockAWS+"\n"), 0644); err != nil {
		t.Fatalf("failed to write ephemeral secret file: %v", err)
	}

	// 2. Ephemeral SAST Source File (query.go)
	srcDir := filepath.Join(tempDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("failed to create src dir: %v", err)
	}
	sqlStmt := "fmt.Sprintf(\"" + "SELECT * FROM items WHERE id = '%s'\", id)"
	goCode := "package main\nimport \"fmt\"\nfunc search(id string) {\n\tquery := " + sqlStmt + "\n\t_ = query\n}\n"
	if err := os.WriteFile(filepath.Join(srcDir, "query.go"), []byte(goCode), 0644); err != nil {
		t.Fatalf("failed to write ephemeral go file: %v", err)
	}

	// 3. Ephemeral Dockerfile
	dockerContent := `FROM alpine:latest
ENV SECRET_KEY=1234567890
CMD ["sh"]
`
	if err := os.WriteFile(filepath.Join(tempDir, "Dockerfile"), []byte(dockerContent), 0644); err != nil {
		t.Fatalf("failed to write ephemeral Dockerfile: %v", err)
	}

	result, err := RunInternalScanner(tempDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Errorf("expected files to be scanned, got 0")
	}

	if len(result.Findings) == 0 {
		t.Errorf("expected findings in ephemeral project, got 0")
	}

	foundSecret := false
	foundSQL := false
	foundDocker := false

	for _, f := range result.Findings {
		if f.Category == "secret" {
			foundSecret = true
		}
		if f.Title == "Potential SQL Injection" {
			foundSQL = true
		}
		if f.Category == "docker" {
			foundDocker = true
		}
	}

	if !foundSecret {
		t.Errorf("expected at least one secret finding in ephemeral project")
	}
	if !foundSQL {
		t.Errorf("expected Potential SQL injection finding in ephemeral project")
	}
	if !foundDocker {
		t.Errorf("expected docker finding in ephemeral project")
	}
}

func TestInternalScannerExclusions(t *testing.T) {
	tempDir := t.TempDir()

	// Create .vibeguard/config.json with exclusions
	vgDir := filepath.Join(tempDir, ".vibeguard")
	if err := os.MkdirAll(vgDir, 0755); err != nil {
		t.Fatalf("failed to create .vibeguard dir: %v", err)
	}
	cfgJSON := `{
  "secret_scan": true,
  "source_scan": true,
  "dependency_scan": false,
  "exclude": ["excluded_dir", "secret.go"]
}`
	if err := os.WriteFile(filepath.Join(vgDir, "config.json"), []byte(cfgJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Create excluded file containing a secret
	excDir := filepath.Join(tempDir, "excluded_dir")
	if err := os.MkdirAll(excDir, 0755); err != nil {
		t.Fatalf("failed to create excluded dir: %v", err)
	}
	secretContent := "package main\nconst key = \"" + string([]byte{'A', 'K', 'I', 'A'}) + "IOSFODNN7EXAMPLE\"\n"
	if err := os.WriteFile(filepath.Join(excDir, "secret.go"), []byte(secretContent), 0644); err != nil {
		t.Fatalf("failed to write excluded file: %v", err)
	}

	// Create non-excluded file
	if err := os.WriteFile(filepath.Join(tempDir, "safe.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("failed to write safe file: %v", err)
	}

	cacheDir := filepath.Join(tempDir, ".vibeguard", "cache", "osv")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create VibeGuard cache directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "cached.json"), []byte(`{"private_key":"-----BEGIN `+"PRIVATE KEY-----"+`"}`), 0644); err != nil {
		t.Fatalf("failed to write VibeGuard cache fixture: %v", err)
	}

	result, err := RunInternalScanner(tempDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	// Verify excluded files are not reported as findings
	for _, f := range result.Findings {
		if f.File == "excluded_dir/secret.go" {
			t.Errorf("excluded file %s was scanned and reported as finding", f.File)
		}
		if filepath.ToSlash(f.File) == ".vibeguard/cache/osv/cached.json" {
			t.Errorf("VibeGuard cache file %s was scanned and reported as finding", f.File)
		}
	}
}
