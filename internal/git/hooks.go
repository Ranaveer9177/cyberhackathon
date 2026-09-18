package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HookMarker   = "# VibeGuard Security Gate — Do not edit this section"
	UserHookFile = "pre-push.user"
)

// HookScriptContent generates the shell script for .git/hooks/pre-push.
func HookScriptContent() string {
	return `#!/bin/sh
` + HookMarker + `

# 1. Run preserved user hook first if present
HOOK_DIR=$(dirname "$0")
if [ -f "$HOOK_DIR/` + UserHookFile + `" ]; then
    "$HOOK_DIR/` + UserHookFile + `" "$@"
    USER_EXIT=$?
    if [ $USER_EXIT -ne 0 ]; then
        exit $USER_EXIT
    fi
fi

# 2. Run VibeGuard security verification gate
vibeguard scan . --hook
exit $?
`
}

// IsHookInstalled checks if the pre-push hook is installed with VibeGuard marker.
func IsHookInstalled(repoPath string) bool {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return false
	}

	hookPath := filepath.Join(root, ".git", "hooks", "pre-push")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), HookMarker)
}

// InstallHook installs the pre-push hook, preserving any existing non-VibeGuard hook as pre-push.user.
func InstallHook(repoPath string) error {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-push")
	userBackupPath := filepath.Join(hooksDir, UserHookFile)

	// If hook exists
	if existingData, err := os.ReadFile(hookPath); err == nil {
		existingStr := string(existingData)
		if strings.Contains(existingStr, HookMarker) {
			// Already our hook, overwrite with latest version
			return os.WriteFile(hookPath, []byte(HookScriptContent()), 0755)
		}

		// Existing user hook found: back it up to pre-push.user
		if err := os.WriteFile(userBackupPath, existingData, 0755); err != nil {
			return fmt.Errorf("failed to backup existing user hook: %w", err)
		}
	}

	return os.WriteFile(hookPath, []byte(HookScriptContent()), 0755)
}

// UninstallHook removes the VibeGuard pre-push hook and restores user backup if present.
func UninstallHook(repoPath string) error {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(root, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "pre-push")
	userBackupPath := filepath.Join(hooksDir, UserHookFile)

	data, err := os.ReadFile(hookPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Verify it's a VibeGuard hook before deleting
	if !strings.Contains(string(data), HookMarker) {
		return fmt.Errorf("pre-push hook does not appear to be managed by VibeGuard")
	}

	// Remove hook
	if err := os.Remove(hookPath); err != nil {
		return err
	}

	// Restore backup if exists
	if _, err := os.Stat(userBackupPath); err == nil {
		return os.Rename(userBackupPath, hookPath)
	}

	return nil
}
