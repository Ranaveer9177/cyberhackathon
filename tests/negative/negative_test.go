package negative_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestNegativeCasesZeroFalsePositives(t *testing.T) {
	// Create a clean isolated directory containing only safe examples
	tmpDir, err := os.MkdirTemp("", "vg-negative-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixturesDir, err := filepath.Abs("../fixtures")
	if err != nil {
		t.Fatalf("failed to resolve fixtures dir: %v", err)
	}

	safeFiles := []string{
		filepath.Join(fixturesDir, "python", "sqli_safe.py"),
		filepath.Join(fixturesDir, "python", "cmdi_safe.py"),
		filepath.Join(fixturesDir, "javascript", "safe.js"),
		filepath.Join(fixturesDir, "typescript", "safe.ts"),
		filepath.Join(fixturesDir, "go", "safe.go"),
		filepath.Join(fixturesDir, "java", "Safe.java"),
	}

	for _, src := range safeFiles {
		content, readErr := os.ReadFile(src)
		if readErr != nil {
			t.Fatalf("failed to read safe fixture %s: %v", src, readErr)
		}
		dst := filepath.Join(tmpDir, filepath.Base(src))
		if writeErr := os.WriteFile(dst, content, 0644); writeErr != nil {
			t.Fatalf("failed to copy safe fixture %s: %v", dst, writeErr)
		}
	}

	result, err := scanner.RunInternalScanner(tmpDir)
	if err != nil {
		t.Fatalf("scanner failed: %v", err)
	}

	for _, f := range result.Findings {
		t.Errorf("unexpected false positive finding in safe code: [%s] %s at %s:%d (evidence: %s)",
			f.ID, f.Title, f.File, f.Line, f.Evidence)
	}
}
