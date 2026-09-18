package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookInstallUninstallAndPreserve(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	// Initially not installed
	if IsHookInstalled(repo) {
		t.Errorf("expected hook to not be installed initially")
	}

	// Install hook
	if err := InstallHook(repo); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	if !IsHookInstalled(repo) {
		t.Errorf("expected hook to be reported as installed")
	}

	hookPath := filepath.Join(repo, ".git", "hooks", "pre-push")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook script: %v", err)
	}
	if !strings.Contains(string(content), HookMarker) {
		t.Errorf("hook script does not contain HookMarker")
	}

	// Uninstall hook
	if err := UninstallHook(repo); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	if IsHookInstalled(repo) {
		t.Errorf("expected hook to be uninstalled")
	}
}

func TestPreserveUserHook(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	hooksDir := filepath.Join(repo, ".git", "hooks")
	os.MkdirAll(hooksDir, 0755)
	hookPath := filepath.Join(hooksDir, "pre-push")
	userScript := "#!/bin/sh\necho 'custom user hook running'\nexit 0\n"
	if err := os.WriteFile(hookPath, []byte(userScript), 0755); err != nil {
		t.Fatalf("failed to create user hook: %v", err)
	}

	// Install VibeGuard hook
	if err := InstallHook(repo); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	// Verify backup was created
	backupPath := filepath.Join(hooksDir, UserHookFile)
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read user hook backup: %v", err)
	}
	if string(backupData) != userScript {
		t.Errorf("backup content mismatch: got %q, want %q", string(backupData), userScript)
	}

	// Verify wrapper runs backup
	wrapperData, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read wrapper hook: %v", err)
	}
	if !strings.Contains(string(wrapperData), UserHookFile) {
		t.Errorf("wrapper hook does not reference %s", UserHookFile)
	}

	// Uninstall should restore original hook
	if err := UninstallHook(repo); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	restoredData, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read restored hook: %v", err)
	}
	if string(restoredData) != userScript {
		t.Errorf("restored hook mismatch: got %q, want %q", string(restoredData), userScript)
	}
}
