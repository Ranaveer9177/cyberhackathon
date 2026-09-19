package git

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindGitRoot locates the root of the Git repository by walking upwards.
func FindGitRoot(startDir string) (string, error) {
	curr, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(curr, ".git")
		if fi, err := os.Stat(gitDir); err == nil && (fi.IsDir() || !fi.IsDir()) {
			return curr, nil
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	return "", fmt.Errorf("not a git repository (or any of the parent directories)")
}

// IsGitRepo checks if the specified path contains a .git directory.
func IsGitRepo(path string) bool {
	gitDir := filepath.Join(path, ".git")
	fi, err := os.Stat(gitDir)
	return err == nil && (fi.IsDir() || !fi.IsDir())
}

// GetBranch returns the current active Git branch name.
func GetBranch(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetRemoteName returns the name of the first git remote (usually "origin").
func GetRemoteName(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "remote")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 && lines[0] != "" {
		return strings.TrimSpace(lines[0])
	}
	return "origin"
}

// GetRemoteURL returns the URL of the specified remote (defaults to origin).
func GetRemoteURL(path, remoteName string) string {
	if remoteName == "" {
		remoteName = "origin"
	}
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "remote", "get-url", remoteName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetRemote returns the remote URL for origin.
func GetRemote(path string) string {
	return GetRemoteURL(path, "origin")
}

// GetCommitHash returns the short commit hash of HEAD.
func GetCommitHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "--short", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetFullCommitHash returns the full commit hash of HEAD.
func GetFullCommitHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetUpstreamHash returns the commit hash of the upstream branch (@{u}).
func GetUpstreamHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "@{u}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetChangedFiles returns a list of files pending push or currently modified.
func GetChangedFiles(path string) []string {
	root, err := FindGitRoot(path)
	if err != nil {
		return nil
	}

	fileMap := make(map[string]bool)
	var files []string

	// 1. Files modified vs HEAD (staged or unstaged)
	if out, err := runGit(root, "diff", "--name-only", "HEAD"); err == nil && strings.TrimSpace(out) != "" {
		for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
			f = strings.TrimSpace(f)
			if f != "" && !fileMap[f] {
				fileMap[f] = true
				files = append(files, f)
			}
		}
	}

	// 2. Untracked or newly staged files from status
	if out, err := runGit(root, "status", "--porcelain"); err == nil && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 3 {
				f := strings.TrimSpace(line[3:])
				if parts := strings.Split(f, " -> "); len(parts) == 2 {
					f = parts[1]
				}
				if f != "" && !fileMap[f] {
					fileMap[f] = true
					files = append(files, f)
				}
			}
		}
	}

	// 3. Commits pending push vs upstream
	if out, err := runGit(root, "diff", "--name-only", "@{u}..HEAD"); err == nil && strings.TrimSpace(out) != "" {
		for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
			f = strings.TrimSpace(f)
			if f != "" && !fileMap[f] {
				fileMap[f] = true
				files = append(files, f)
			}
		}
	}

	return files
}

// HasStagedChanges checks if there are uncommitted staged changes in git index.
func HasStagedChanges(path string) bool {
	root, err := FindGitRoot(path)
	if err != nil {
		return false
	}
	// git diff --cached --quiet exits with 1 if there are staged changes, 0 if clean
	cmd := exec.Command("git", "diff", "--cached", "--quiet")
	cmd.Dir = root
	err = cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return true
		}
	}
	return false
}

// GitAdd stages all changes (`git add .`).
func GitAdd(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	_, err = runGit(root, "add", ".")
	return err
}

// GitCommit creates a commit with the specified message (`git commit -m <message>`).
func GitCommit(path string, message string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	_, err = runGit(root, "commit", "-m", message)
	return err
}

// GitPush executes `git push`.
func GitPush(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "push")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// GitPushVerified executes `git push --no-verify` after VibeGuard has already completed full verification.
func GitPushVerified(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "push", "--no-verify")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Helper to run git commands and capture stdout
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// PushRef represents a Git ref update passed via stdin to a pre-push hook.
type PushRef struct {
	LocalRef  string
	LocalSHA  string
	RemoteRef string
	RemoteSHA string
}

// ReadPrePushRefs reads standard Git pre-push ref update tuples from an io.Reader.
func ReadPrePushRefs(r io.Reader) ([]PushRef, error) {
	var refs []PushRef
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			refs = append(refs, PushRef{
				LocalRef:  parts[0],
				LocalSHA:  parts[1],
				RemoteRef: parts[2],
				RemoteSHA: parts[3],
			})
		}
	}
	return refs, scanner.Err()
}

// ReadAllPushedRefs reads standard Git pre-push ref update tuples from stdin if present.
func ReadAllPushedRefs() ([]PushRef, error) {
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) != 0 {
		return nil, nil
	}
	return ReadPrePushRefs(os.Stdin)
}

// GetPushedRefs reads standard Git pre-push ref update tuples from stdin if present.
func GetPushedRefs() (localRef, localSha, remoteRef, remoteSha string) {
	refs, err := ReadAllPushedRefs()
	if err == nil && len(refs) > 0 {
		return refs[0].LocalRef, refs[0].LocalSHA, refs[0].RemoteRef, refs[0].RemoteSHA
	}
	return "", "", "", ""
}

// CreatePushSnapshot extracts the tree at localSha into a temporary directory using Go's archive/tar.
func CreatePushSnapshot(repoPath, localSha string) (string, error) {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return "", err
	}

	tempDir, err := os.MkdirTemp("", "vibeguard-push-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	cmd := exec.Command("git", "archive", "--format=tar", localSha)
	cmd.Dir = root
	out, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to start git archive: %w", err)
	}

	tr := tar.NewReader(out)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			os.RemoveAll(tempDir)
			return "", fmt.Errorf("failed reading tar: %w", err)
		}

		target := filepath.Join(tempDir, filepath.FromSlash(header.Name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				os.RemoveAll(tempDir)
				return "", err
			}
			outFile.Close()
		}
	}

	if err := cmd.Wait(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("git archive failed: %v: %s", err, stderr.String())
	}

	return tempDir, nil
}

// GetPushedCommitFiles returns the list of files touched in the exact commits being pushed.
func GetPushedCommitFiles(repoPath, remoteSha, localSha string) []string {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return nil
	}

	var files []string
	seen := make(map[string]bool)

	var out string
	if remoteSha == "" || strings.Trim(remoteSha, "0") == "" {
		out, _ = runGit(root, "diff-tree", "--no-commit-id", "--name-only", "-r", localSha)
	} else {
		out, _ = runGit(root, "diff", "--name-only", remoteSha+".."+localSha)
	}

	for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
		f = strings.TrimSpace(f)
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files
}

// GetPushedCommitDiff returns the raw unified diff for the commits being pushed.
func GetPushedCommitDiff(repoPath, remoteSha, localSha string) string {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return ""
	}

	if remoteSha == "" || strings.Trim(remoteSha, "0") == "" {
		out, _ := runGit(root, "show", localSha)
		return out
	}
	out, _ := runGit(root, "diff", remoteSha+".."+localSha)
	return out
}
