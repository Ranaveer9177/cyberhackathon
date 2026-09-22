package dependencies

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectDependenciesExcludesVibeGuardCache(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, ".vibeguard", "cache", "osv")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create cache directory: %v", err)
	}
	cacheLock := `{"packages":{"node_modules/cache-only":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(cacheDir, "package-lock.json"), []byte(cacheLock), 0644); err != nil {
		t.Fatalf("failed to write cache lockfile: %v", err)
	}

	deps, err := DetectDependencies(root)
	if err != nil {
		t.Fatalf("DetectDependencies failed: %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("expected no dependencies from VibeGuard cache, got %v", deps)
	}
}
