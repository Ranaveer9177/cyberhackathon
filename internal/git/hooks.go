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

# 2. Resolve repository root
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
    REPO_ROOT=$(pwd)
fi

# 3. Locate VibeGuard binary
VIBEGUARD_BIN=""
if [ -f "$REPO_ROOT/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$REPO_ROOT/vibeguard.exe"
elif [ -f "$REPO_ROOT/vibeguard" ]; then
    VIBEGUARD_BIN="$REPO_ROOT/vibeguard"
elif [ -n "$LOCALAPPDATA" ] && [ -f "$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe"
elif [ -n "$USERPROFILE" ] && [ -f "$USERPROFILE/AppData/Local/VibeGuard/bin/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$USERPROFILE/AppData/Local/VibeGuard/bin/vibeguard.exe"
elif command -v vibeguard.exe >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard.exe"
elif command -v vibeguard >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard"
fi

if [ -z "$VIBEGUARD_BIN" ]; then
    echo "Notice: VibeGuard binary not found in repository root or PATH. Allowing push."
    exit 0
fi

# 4. Run VibeGuard security verification gate
"$VIBEGUARD_BIN" scan "$REPO_ROOT" --hook
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
