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

func TestRuleCWEParity(t *testing.T) {
	ruleIDs := []string{
		"VG-SAST-001", "VG-SAST-002", "VG-SAST-003", "VG-SAST-004", "VG-SAST-005",
		"VG-SAST-006", "VG-SAST-007", "VG-SAST-008", "VG-AUTH-001", "VG-AUTH-002",
		"VG-AUTH-003", "VG-WEBHOOK-001", "VG-SEC-001", "VG-SEC-002", "VG-SEC-003",
		"VG-SEC-004", "VG-SEC-005", "VG-SECRET-001", "VG-SECRET-002", "VG-SECRET-003",
		"VG-SECRET-FILE", "VG-DCK-001", "VG-DCK-002", "VG-DCK-003", "VG-DCK-004",
		"VG-DCK-005", "VG-DCK-006", "VG-DCK-007", "VG-DCK-008", "VG-DCK-009",
		"VG-DCK-010", "VG-DCK-011", "VG-DCK-012", "VG-DCK-013", "VG-DCK-014",
		"VG-DCK-015", "VG-DCK-016", "VG-CFG-001", "VG-CFG-002", "VG-CFG-003",
		"VG-CFG-004", "VG-CFG-005", "VG-GIT-001",
	}

	for _, id := range ruleIDs {
		cwe := RuleCWE(id)
		if cwe == "" {
			t.Errorf("rule %s has empty CWE mapping", id)
		}
	}
}

func TestInternalRulesPositiveNegative(t *testing.T) {
	rules := getInternalRules()
	ruleMap := make(map[string]internalRule)
	for _, r := range rules {
		ruleMap[r.id] = r
	}

	// 1. VG-SAST-003 Dangerous Eval
	evalRule, ok := ruleMap["VG-SAST-003"]
	if !ok {
		t.Fatalf("VG-SAST-003 not found in internal rules")
	}
	if !evalRule.pattern.MatchString("eval(payload)") {
		t.Errorf("VG-SAST-003 failed positive match on eval(payload)")
	}
	if evalRule.pattern.MatchString("json.loads(payload)") {
		t.Errorf("VG-SAST-003 false positive on json.loads")
	}

	// 2. VG-SAST-004 TLS
	tlsRule, ok := ruleMap["VG-SAST-004"]
	if !ok {
		t.Fatalf("VG-SAST-004 not found in internal rules")
	}
	if !tlsRule.pattern.MatchString("verify=False") {
		t.Errorf("VG-SAST-004 failed positive match on verify=False")
	}
	if tlsRule.pattern.MatchString("verify=True") {
		t.Errorf("VG-SAST-004 false positive on verify=True")
	}

	// 3. VG-SAST-005 Weak Crypto
	cryptoRule, ok := ruleMap["VG-SAST-005"]
	if !ok {
		t.Fatalf("VG-SAST-005 not found in internal rules")
	}
	if !cryptoRule.pattern.MatchString("hashlib.md5()") {
		t.Errorf("VG-SAST-005 failed positive match on md5")
	}
	if cryptoRule.pattern.MatchString("hashlib.sha256()") {
		t.Errorf("VG-SAST-005 false positive on sha256")
	}
}
