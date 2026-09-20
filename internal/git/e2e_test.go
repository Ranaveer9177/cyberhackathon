package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitPrePushHookLifecycle tests full Git hook integration using real temporary local and remote repositories.
func TestGitPrePushHookLifecycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed on host, skipping E2E git tests")
	}

	tempBase := t.TempDir()

	// 1. Create a bare remote repository
	remoteDir := filepath.Join(tempBase, "remote.git")
	cmd := exec.Command("git", "init", "--bare", remoteDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to init bare remote: %v (%s)", err, string(out))
	}

	// 2. Create local repository
	localDir := filepath.Join(tempBase, "local")
	if out, err := exec.Command("git", "init", localDir).CombinedOutput(); err != nil {
		t.Fatalf("failed to init local repo: %v (%s)", err, string(out))
	}

	// Configure local repo git user
	_ = exec.Command("git", "-C", localDir, "config", "user.name", "VibeGuard Test").Run()
	_ = exec.Command("git", "-C", localDir, "config", "user.email", "test@vibeguard.local").Run()
	_ = exec.Command("git", "-C", localDir, "config", "commit.gpgsign", "false").Run()

	// Add remote
	if out, err := exec.Command("git", "-C", localDir, "remote", "add", "origin", remoteDir).CombinedOutput(); err != nil {
		t.Fatalf("failed to add remote origin: %v (%s)", err, string(out))
	}

	// 3. Install VibeGuard pre-push hook
	if err := InstallHook(localDir); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}
	if !IsHookInstalled(localDir) {
		t.Fatal("expected hook to be installed")
	}

	// 4. Test A: Clean Commit & Push
	cleanFile := filepath.Join(localDir, "main.go")
	if err := os.WriteFile(cleanFile, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("failed to write clean file: %v", err)
	}

	if out, err := exec.Command("git", "-C", localDir, "add", "main.go").CombinedOutput(); err != nil {
		t.Fatalf("git add clean file failed: %v (%s)", err, string(out))
	}
	if out, err := exec.Command("git", "-C", localDir, "commit", "-m", "Clean initial commit").CombinedOutput(); err != nil {
		t.Fatalf("git commit clean file failed: %v (%s)", err, string(out))
	}

	// Read commit info
	branch := GetBranch(localDir)
	if branch == "" {
		branch = "main"
	}
	headSHA := GetCommitHash(localDir)
	if headSHA == "" {
		t.Fatal("expected valid HEAD commit hash")
	}

	// Test pushed ref calculation
	refsInput := strings.NewReader("refs/heads/" + branch + " " + headSHA + " refs/heads/" + branch + " 0000000000000000000000000000000000000000\n")
	pushedRefs, err := ReadPrePushRefs(refsInput)
	if err != nil {
		t.Fatalf("ReadPrePushRefs failed: %v", err)
	}
	if len(pushedRefs) != 1 {
		t.Fatalf("expected 1 pushed ref, got %d", len(pushedRefs))
	}
	if pushedRefs[0].LocalSHA != headSHA {
		t.Errorf("expected local SHA %s, got %s", headSHA, pushedRefs[0].LocalSHA)
	}

	// 5. Test Snapshot creation of clean commit
	snapshotDir, err := CreatePushSnapshot(localDir, headSHA)
	if err != nil {
		t.Fatalf("CreatePushSnapshot failed: %v", err)
	}
	defer os.RemoveAll(snapshotDir)

	if _, err := os.Stat(filepath.Join(snapshotDir, "main.go")); os.IsNotExist(err) {
		t.Errorf("expected clean file main.go in push snapshot")
	}

	// 6. Test Hook Uninstall & Restoration
	if err := UninstallHook(localDir); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}
	if IsHookInstalled(localDir) {
		t.Errorf("expected hook to be uninstalled")
	}
}
