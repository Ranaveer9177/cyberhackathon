package git

import (
	"os"
	"path/filepath"
	"testing"
)

func createTestRepo(t *testing.T) string {
	dir, err := os.MkdirTemp("", "vibeguard_git_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git: %v", err)
	}

	return dir
}

func TestIsGitRepo(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	if !IsGitRepo(repo) {
		t.Errorf("expected IsGitRepo to return true for %s", repo)
	}

	nonRepo, err := os.MkdirTemp("", "non_git_repo")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(nonRepo)

	if IsGitRepo(nonRepo) {
		t.Errorf("expected IsGitRepo to return false for non-git directory %s", nonRepo)
	}

	// Test FindGitRoot from subfolder
	subDir := filepath.Join(repo, "cmd", "app")
	os.MkdirAll(subDir, 0755)
	root, err := FindGitRoot(subDir)
	if err != nil {
		t.Fatalf("FindGitRoot failed: %v", err)
	}
	if root != repo {
		t.Errorf("expected root %s, got %s", repo, root)
	}
}

func TestGetChangedFilesAndStagedChanges(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	// In mock directory without git init, HasStagedChanges should return false without crashing
	if HasStagedChanges(repo) {
		t.Errorf("expected HasStagedChanges to return false in empty mock repo")
	}

	files := GetChangedFiles(repo)
	if len(files) != 0 {
		t.Errorf("expected empty changed files, got %v", files)
	}
}
