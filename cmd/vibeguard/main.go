package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/baseline"
	"github.com/vibeguard/vibeguard/internal/config"
	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/git"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/report"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const version = "4.4.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := strings.ToLower(os.Args[1])

	switch command {
	case "init":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleInit(targetDir)
		os.Exit(0)

	case "uninstall":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleUninstall(targetDir)
		os.Exit(0)

	case "status":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleStatus(targetDir)
		os.Exit(0)

	case "push":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		exitCode := handlePush(targetDir)
		os.Exit(exitCode)

	case "scan":
		projectPath, format, outputPath, isHook, err := parseScanArgs(os.Args[2:], "terminal")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if strings.Contains(err.Error(), "unsupported output format") || strings.Contains(err.Error(), "missing format") {
				os.Exit(3)
			}
			os.Exit(2)
		}
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := runScan(projectPath, format, outputPath, isHook)
		os.Exit(exitCode)

	case "report":
		projectPath, format, outputPath, isHook, err := parseScanArgs(os.Args[2:], "html")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if strings.Contains(err.Error(), "unsupported output format") || strings.Contains(err.Error(), "missing format") {
				os.Exit(3)
			}
			os.Exit(2)
		}
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := runScan(projectPath, format, outputPath, isHook)
		os.Exit(exitCode)

	case "version", "--version", "-v":
		fmt.Printf("VibeGuard v%s\n", version)
		os.Exit(0)

	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(2)
	}
}

func parseScanArgs(args []string, defaultFormat string) (projectPath, format, outputPath string, isHook bool, err error) {
	format = defaultFormat
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if (arg == "--format" || arg == "-f") {
			if i+1 < len(args) {
				format = args[i+1]
				i++
			} else {
				return "", "", "", false, fmt.Errorf("Error: missing format argument\nSupported formats: terminal, json, html, sarif")
			}
		} else if (arg == "--output" || arg == "-o") {
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			} else {
				return "", "", "", false, fmt.Errorf("Error: missing output path argument")
			}
		} else if arg == "--hook" {
			isHook = true
		} else if arg == "--offline" {
			osv.SetOfflineMode(true)
		} else if !strings.HasPrefix(arg, "-") && projectPath == "" {
			projectPath = arg
		} else if strings.HasPrefix(arg, "-") {
			return "", "", "", false, fmt.Errorf("Error: unknown option '%s'", arg)
		}
	}

	normFormat := strings.ToLower(format)
	switch normFormat {
	case "terminal", "json", "html", "sarif":
		format = normFormat
	default:
		return "", "", "", false, fmt.Errorf("Error: unsupported output format: %s\nSupported formats: terminal, json, html, sarif", format)
	}

	return projectPath, format, outputPath, isHook, nil
}

func printUsage() {
	fmt.Printf("VibeGuard v%s — Pre-Deployment & Git Secure Push Verification CLI\n", version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  vibeguard init [<repo-path>]                     Install Git pre-push hook & initialize .vibeguard/")
	fmt.Println("  vibeguard uninstall [<repo-path>]                Remove VibeGuard Git pre-push hook")
	fmt.Println("  vibeguard status [<repo-path>]                   Show Git repository and security gate status")
	fmt.Println("  vibeguard push [<repo-path>]                     Controlled commit + scan + push interactive workflow")
	fmt.Println("  vibeguard scan [<project-path>] [options]        Run security scan")
	fmt.Println("  vibeguard report [<project-path>] [options]      Generate HTML/JSON security report")
	fmt.Println("  vibeguard version                                Show VibeGuard version")
	fmt.Println("  vibeguard help                                   Show this help message")
	fmt.Println()
	fmt.Println("Scan Options:")
	fmt.Println("  --format, -f <fmt>     Output format: terminal (default), json, html, sarif")
	fmt.Println("  --output, -o <path>    Custom report output path (default: reports/scan.json or reports/scan.html)")
	fmt.Println("  --offline              Query only local cached vulnerability intelligence")
	fmt.Println("  --hook                 Apply gate policy thresholds from .vibeguard/config.json")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0  PASS — Security scan passed, safe to deploy/push")
	fmt.Println("  1  BLOCK — Security policy blocked push (critical or high findings)")
	fmt.Println("  2  ERROR — Scanner or runtime error")
	fmt.Println("  3  CONFIG / FORMAT ERROR — Unsupported format or configuration error")
	fmt.Println("  4  OSV UNAVAILABLE — Vulnerability intelligence unreachable with fail_closed enabled")
}

// handleInit: installs hook, creates default config, preserves existing user hook
func handleInit(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		fmt.Fprintln(os.Stderr, "Run 'git init' first, then run 'vibeguard init'.")
		os.Exit(2)
	}

	root, _ := git.FindGitRoot(absDir)
	projectName := filepath.Base(root)

	fmt.Println("========================================")
	fmt.Println("    VIBEGUARD GIT SECURITY GATE INIT")
	fmt.Println("========================================")
	fmt.Printf("Repository: %s\n", projectName)
	fmt.Printf("Path:       %s\n", root)
	fmt.Println()

	// 1. Install Hook
	if err := git.InstallHook(root); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing Git pre-push hook: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("✓ Git pre-push hook installed successfully (.git/hooks/pre-push)")

	// 2. Initialize .vibeguard/config.json if missing
	cfgPath := config.ConfigPath(root)
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := config.CreateDefaultConfig(root); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create default config: %v\n", err)
		} else {
			fmt.Println("✓ Initialized default configuration (.vibeguard/config.json)")
		}
	} else {
		fmt.Println("✓ Existing configuration preserved (.vibeguard/config.json)")
	}

	fmt.Println()
	fmt.Println("Every future 'git push' will automatically run VibeGuard before code leaves your machine.")
	fmt.Println("========================================")
}

// handleUninstall: removes VibeGuard hook and restores user backup if present
func handleUninstall(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		os.Exit(2)
	}

	root, _ := git.FindGitRoot(absDir)
	if err := git.UninstallHook(root); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing Git hook: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("✓ VibeGuard Git pre-push hook removed successfully.")
}

// handleStatus: prints repository and security gate status
func handleStatus(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("========================================")
	fmt.Println("      VIBEGUARD V2 — STATUS")
	fmt.Println("========================================")

	if !git.IsGitRepo(absDir) {
		fmt.Printf("Directory:     %s\n", absDir)
		fmt.Println("Git detected:  NO")
		fmt.Println("Status:        INACTIVE (not a git repository)")
		fmt.Println("========================================")
		return
	}

	root, _ := git.FindGitRoot(absDir)
	branch := git.GetBranch(root)
	remote := git.GetRemote(root)
	commit := git.GetCommitHash(root)
	hookInstalled := git.IsHookInstalled(root)

	fmt.Printf("Repository:     %s\n", root)
	fmt.Printf("Git detected:   YES\n")
	if branch != "" {
		fmt.Printf("Branch:         %s\n", branch)
	}
	if remote != "" {
		fmt.Printf("Remote:         %s\n", remote)
	}
	if commit != "" {
		fmt.Printf("Commit:         %s\n", commit)
	}

	if hookInstalled {
		fmt.Println("Pre-push hook:  INSTALLED (.git/hooks/pre-push)")
		fmt.Println("VibeGuard Gate: ACTIVE")
	} else {
		fmt.Println("Pre-push hook:  NOT INSTALLED")
		fmt.Println("VibeGuard Gate: INACTIVE (run 'vibeguard init' to enable)")
	}

	// Configuration
	cfg, err := config.LoadConfig(root)
	if err == nil {
		fmt.Printf("Config policy:  Block on %s\n", strings.Join(cfg.BlockOn, ", "))
		fmt.Printf("Scan mode:      %s\n", cfg.ScanMode)
		fmt.Printf("Fail closed:    %v\n", cfg.FailClosed)
	}

	fmt.Println("========================================")
}

// handlePush: controlled interactive commit + scan + push workflow
func handlePush(dir string) int {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		return 2
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		return 2
	}

	root, _ := git.FindGitRoot(absDir)

	fmt.Println("========================================")
	fmt.Println("       VIBEGUARD SECURE PUSH")
	fmt.Println("========================================")
	fmt.Println()

	// 1. Check for staged / changed files
	changed := git.GetChangedFiles(root)
	hasStaged := git.HasStagedChanges(root)
	reader := bufio.NewReader(os.Stdin)

	if hasStaged {
		fmt.Println("Detected changes already staged in Git index.")
	} else if len(changed) == 0 {
		fmt.Println("No modified or staged files detected in repository.")
		return 0
	} else {
		fmt.Printf("Modified files (%d):\n", len(changed))
		maxShow := 5
		for i, f := range changed {
			if i < maxShow {
				fmt.Printf("  • %s\n", f)
			}
		}
		if len(changed) > maxShow {
			fmt.Printf("  ... and %d more file(s)\n", len(changed)-maxShow)
		}
		fmt.Println()

		fmt.Print("Stage these modified files for commit? [Y/n]: ")
		stageAns, _ := reader.ReadString('\n')
		stageAns = strings.TrimSpace(strings.ToLower(stageAns))
		if stageAns != "" && stageAns != "y" && stageAns != "yes" {
			fmt.Println("Aborted: files were not staged. Stage desired files manually with 'git add <file>'.")
			return 0
		}

		fmt.Println("Staging changes (git add .)...")
		if err := git.GitAdd(root); err != nil {
			fmt.Fprintf(os.Stderr, "git add failed: %v\n", err)
			return 2
		}
	}

	// 2. Prompt for commit message
	fmt.Print("Enter commit message: ")
	commitMsg, _ := reader.ReadString('\n')
	commitMsg = strings.TrimSpace(commitMsg)
	if commitMsg == "" {
		fmt.Fprintln(os.Stderr, "Aborted: commit message cannot be empty.")
		return 2
	}

	// 3. git commit -m <message>
	fmt.Println("Creating commit...")
	if err := git.GitCommit(root, commitMsg); err != nil {
		fmt.Fprintf(os.Stderr, "git commit failed: %v\n", err)
		return 2
	}

	// 5. Run full security scan using exact same push verification model
	fmt.Println()
	fmt.Println("Running VibeGuard security verification scan...")
	branch := git.GetBranch(root)
	commitHash := git.GetFullCommitHash(root)
	upstreamHash := git.GetUpstreamHash(root)
	explicitRefs := []git.PushRef{
		{
			LocalRef:  "refs/heads/" + branch,
			LocalSHA:  commitHash,
			RemoteRef: "refs/heads/" + branch,
			RemoteSHA: upstreamHash,
		},
	}
	exitCode := runScanWithRefs(root, "terminal", "", true, explicitRefs, true)
	if exitCode != 0 {
		fmt.Println()
		fmt.Println("========================================")
		fmt.Println("  STATUS: PUSH BLOCKED")
		fmt.Println("  Security findings detected.")
		fmt.Println("  Commit created locally, but will NOT be pushed.")
		fmt.Println("  Resolve findings and run 'git push' when ready.")
		fmt.Println("========================================")
		return 1
	}

	// 6. If PASS -> prompt "Push to GitHub? [Y/n]"
	fmt.Println()
	fmt.Print("Push to GitHub? [Y/n]: ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))

	if ans == "" || ans == "y" || ans == "yes" {
		fmt.Println("Pushing to remote (git push --no-verify)...")
		if err := git.GitPushVerified(root); err != nil {
			fmt.Fprintf(os.Stderr, "git push failed: %v\n", err)
			return 2
		}
		fmt.Println("✓ Push to remote completed successfully!")
		return 0
	}

	fmt.Println("Push skipped by user. Local commit is preserved.")
	return 0
}

func promptConsole(promptText string) (string, error) {
	if os.Getenv("CI") != "" || os.Getenv("VIBEGUARD_NON_INTERACTIVE") != "" {
		fmt.Println(promptText + "Y (non-interactive)")
		return "y", nil
	}
	fmt.Print(promptText)
	var f *os.File
	var err error
	if runtime.GOOS == "windows" {
		f, err = os.Open("CONIN$")
	} else {
		f, err = os.Open("/dev/tty")
	}
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		ans, err := reader.ReadString('\n')
		return strings.TrimSpace(ans), err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	ans, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(ans), nil
}

func determineOSVSeverity(v osv.Vulnerability) string {
	return osv.DetermineSeverity(v)
}



func runScan(projectPath string, format string, customOutput string, isHook bool) int {
	return runScanWithRefs(projectPath, format, customOutput, isHook, nil, false)
}

func runScanWithRefs(projectPath string, format string, customOutput string, isHook bool, explicitRefs []git.PushRef, isVibePush bool) int {
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid project path: %v\n", err)
		return 2
	}

	info, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Project path does not exist: %s\n", absPath)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot access project path: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: project path is not a directory: %s\n", absPath)
		return 2
	}

	// Load configuration
	cfg, err := config.LoadConfig(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration Error: %v\n", err)
		return 3
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration Error: %v\n", err)
		return 3
	}

	if git.IsGitRepo(absPath) && isHook {
		root, _ := git.FindGitRoot(absPath)
		pushedRefs := explicitRefs
		if len(pushedRefs) == 0 {
			pushedRefs, _ = git.ReadAllPushedRefs()
		}

		if len(pushedRefs) == 0 {
			return scanSingleTarget(absPath, root, cfg, format, customOutput, true, nil, isVibePush, false)
		}

		var activeRefs []git.PushRef
		for _, pr := range pushedRefs {
			if strings.Trim(pr.LocalSHA, "0") == "" {
				continue // branch deletion
			}
			if pr.LocalSHA == pr.RemoteSHA {
				continue // already up to date on remote
			}
			activeRefs = append(activeRefs, pr)
		}

		if len(activeRefs) == 0 {
			return scanSingleTarget(absPath, root, cfg, format, customOutput, true, nil, isVibePush, false)
		}

		overallExitCode := 0
		failedCount := 0
		skipPrompt := len(activeRefs) > 1

		for idx, pRef := range activeRefs {
			if len(activeRefs) > 1 {
				fmt.Printf("\n========================================\n")
				fmt.Printf(" Verifying Pushed Ref [%d/%d]: %s\n", idx+1, len(activeRefs), pRef.RemoteRef)
				fmt.Printf("========================================\n")
			}

			code := scanSingleTarget(absPath, root, cfg, format, customOutput, true, &pRef, isVibePush, skipPrompt)
			if code != 0 {
				overallExitCode = code
				failedCount++
			}
		}

		if len(activeRefs) > 1 {
			fmt.Println()
			fmt.Println("========================================")
			if overallExitCode == 0 {
				fmt.Printf("STATUS: ALL %d PUSHED REFS PASSED\n", len(activeRefs))
				if isHook && !isVibePush {
					fmt.Println()
					ans, err := promptConsole("Proceed with Git push? [Y/N]: ")
					if err != nil {
						fmt.Println("Continuing Git push...")
						return 0
					}
					lower := strings.ToLower(ans)
					if lower == "n" || lower == "no" {
						fmt.Println("Push cancelled by user.")
						return 1
					}
					fmt.Println("Continuing Git push...")
					return 0
				}
			} else {
				fmt.Printf("STATUS: PUSH BLOCKED (%d of %d refs failed security gate)\n", failedCount, len(activeRefs))
			}
			fmt.Println("========================================")
		}

		return overallExitCode
	}

	// Single target scan (CLI scan, report command, or working tree scan)
	return scanSingleTarget(absPath, absPath, cfg, format, customOutput, isHook, nil, isVibePush, false)
}

func scanSingleTarget(absPath string, root string, cfg *config.Config, format string, customOutput string, isHook bool, pRef *git.PushRef, isVibePush bool, skipPrompt bool) int {
	projectName := filepath.Base(absPath)
	scanStart := time.Now()

	var commitHash, branchName, remoteURL string
	var pushedCommitDiff string
	var pushedFiles []string
	targetScanPath := absPath
	var cleanupSnapshot func()

	if git.IsGitRepo(absPath) {
		commitHash = git.GetCommitHash(root)
		branchName = git.GetBranch(root)
		remoteName := git.GetRemoteName(root)
		remoteURL = git.GetRemoteURL(root, remoteName)

		if isHook && pRef != nil {
			commitHash = pRef.LocalSHA
			if len(commitHash) > 7 {
				commitHash = commitHash[:7]
			}
			if pRef.RemoteRef != "" {
				remoteURL = pRef.RemoteRef
			}

			pushedFiles = git.GetPushedCommitFiles(root, pRef.RemoteSHA, pRef.LocalSHA)
			pushedCommitDiff = git.GetPushedCommitDiff(root, pRef.RemoteSHA, pRef.LocalSHA)

			// Create push snapshot of local commit so we scan the exact committed tree
			snapshotDir, err := git.CreatePushSnapshot(root, pRef.LocalSHA)
			if err == nil {
				targetScanPath = snapshotDir
				cleanupSnapshot = func() {
					os.RemoveAll(snapshotDir)
				}
				// Copy repo config to snapshot if absent
				snapCfgDir := filepath.Join(snapshotDir, ".vibeguard")
				_ = os.MkdirAll(snapCfgDir, 0755)
				cfgBytes, _ := os.ReadFile(config.ConfigPath(root))
				if len(cfgBytes) > 0 {
					_ = os.WriteFile(config.ConfigPath(snapshotDir), cfgBytes, 0644)
				}
			}
		}
	}
	if cleanupSnapshot != nil {
		defer cleanupSnapshot()
	}

	// Banner
	if isHook || isVibePush {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY GATE")
		fmt.Println("========================================")
		fmt.Println()
	} else {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY SCANNER")
		fmt.Println("========================================")
		fmt.Println()
	}

	passStr := report.ColorGreen + "PASS" + report.ColorReset
	failStr := report.ColorRed + "FAIL" + report.ColorReset

	// Step 1: Detecting project
	fmt.Printf("[1/5] Detecting project ........ %s\n", passStr)

	// Step 2 & 3: Run scanner for secrets & source code
	scanResult, err := scanner.RunScanner(targetScanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Scanner error: %v\n", err)
		if cfg.FailClosed {
			fmt.Fprintln(os.Stderr, "Security policy failure: fail_closed is enabled.")
			return 2
		}
		scanResult = &scanner.ScanResult{
			Project:  projectName,
			Findings: []scanner.Finding{},
		}
	}
	for i := range scanResult.Findings {
		f := &scanResult.Findings[i]
		if rel, err := filepath.Rel(targetScanPath, f.File); err == nil && !strings.HasPrefix(rel, "..") {
			f.File = filepath.ToSlash(rel)
		}
	}

	// Combine findings
	allFindings := make([]scanner.Finding, len(scanResult.Findings))
	copy(allFindings, scanResult.Findings)

	// Scan pushed commit diff for secrets that exist in the commit history even if removed from working tree
	if pushedCommitDiff != "" && cfg.SecretScan {
		secretPatterns := []struct {
			name string
			re   *regexp.Regexp
		}{
			{"AWS Access Key in Pushed Commit", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{"Generic API Key in Pushed Commit", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}`)},
			{"Private Key in Pushed Commit", regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`)},
			{"Password Assignment in Pushed Commit", regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`)},
		}

		diffLines := strings.Split(pushedCommitDiff, "\n")
		var currentFile string
		for _, dLine := range diffLines {
			if strings.HasPrefix(dLine, "diff --git a/") {
				rest := strings.TrimPrefix(dLine, "diff --git a/")
				if idx := strings.LastIndex(rest, " b/"); idx != -1 {
					currentFile = rest[:idx]
				} else {
					currentFile = rest
				}
				currentFile = strings.Trim(currentFile, "\"")
			}
			if currentFile != "" && cfg.IsExcluded(currentFile) {
				continue
			}
			if strings.HasPrefix(dLine, "+") && !strings.HasPrefix(dLine, "+++") {
				added := dLine[1:]
				for _, sp := range secretPatterns {
					if sp.name == "Password Assignment in Pushed Commit" {
						ext := strings.ToLower(filepath.Ext(currentFile))
						if ext == ".md" || ext == ".markdown" || ext == ".rst" || ext == ".txt" || ext == ".html" || ext == ".htm" || ext == ".adoc" {
							continue
						}
						lineLower := strings.ToLower(added)
						if strings.Contains(lineLower, `"admin"`) || strings.Contains(lineLower, `"password"`) || strings.Contains(lineLower, `""`) || strings.Contains(lineLower, `"..."`) || strings.Contains(lineLower, `read-host`) || strings.Contains(lineLower, `param(`) {
							continue
						}
					}
					if sp.re.MatchString(added) {
						masked := strings.TrimSpace(added)
						if len(masked) > 8 {
							masked = masked[:8] + "****"
						}
						allFindings = append(allFindings, scanner.Finding{
							ID:             fmt.Sprintf("VG-%03d", len(allFindings)+1),
							Category:       "secret",
							Severity:       "CRITICAL",
							Title:          sp.name,
							Description:    "Secret detected in the commit being pushed to remote.",
							File:           currentFile,
							Line:           0,
							Evidence:       masked,
							Recommendation: "Rewrite commit history to remove secret before pushing.",
							Confidence:     "HIGH",
						})
						break
					}
				}
			}
		}
	}

	// Filter findings to only changed files when scan_mode is "changed"
	if isHook && strings.ToLower(cfg.ScanMode) == "changed" && len(pushedFiles) > 0 {
		pushedMap := make(map[string]bool)
		for _, pf := range pushedFiles {
			pushedMap[filepath.ToSlash(filepath.Clean(pf))] = true
		}

		var filteredFindings []scanner.Finding
		for _, f := range allFindings {
			cleanF := filepath.ToSlash(filepath.Clean(f.File))
			if pushedMap[cleanF] {
				filteredFindings = append(filteredFindings, f)
			}
		}
		allFindings = filteredFindings
	}

	// Secret and Source findings evaluation
	secretCount := 0
	sourceCritHighCount := 0
	for _, f := range allFindings {
		if strings.ToLower(f.Category) == "secret" {
			secretCount++
		} else if strings.ToLower(f.Category) != "dependency" {
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				sourceCritHighCount++
			}
		}
	}

	if secretCount > 0 {
		fmt.Printf("[2/5] Secret scan .............. %s\n", failStr)
	} else {
		fmt.Printf("[2/5] Secret scan .............. %s\n", passStr)
	}

	if sourceCritHighCount > 0 {
		fmt.Printf("[3/5] Source scan .............. %s\n", failStr)
	} else {
		fmt.Printf("[3/5] Source scan .............. %s\n", passStr)
	}

	// Step 4: Detect and check dependencies
	var vulnResults []osv.VulnResult
	depCritHighCount := 0
	if cfg.DependencyScan {
		deps, err := dependencies.DetectDependencies(targetScanPath)
		if err != nil {
			deps = []dependencies.Dependency{}
		}

		var osvDeps []osv.DependencyInfo
		for _, d := range deps {
			osvDeps = append(osvDeps, osv.DependencyInfo{
				Name:       d.Name,
				Version:    d.Version,
				Ecosystem:  d.Ecosystem,
				SourceFile: d.SourceFile,
			})
		}

		if len(osvDeps) > 0 {
			var osvErr error
			vulnResults, osvErr = osv.CheckAllDependenciesWithStatus(osvDeps)
			if osvErr != nil && len(osvDeps) > 0 && cfg.FailClosed {
				fmt.Fprintln(os.Stderr, "Security policy failure: OSV unavailable and fail_closed is enabled.")
				return 4
			}
		}

		for _, vr := range vulnResults {
			for _, v := range vr.Vulnerabilities {
				sev := determineOSVSeverity(v)
				if sev == "CRITICAL" || sev == "HIGH" {
					depCritHighCount++
				}
			}
		}
	}

	osvMode := "online"
	if osv.IsOfflineMode() {
		osvMode = "offline/cache"
	}
	if depCritHighCount > 0 {
		fmt.Printf("[4/5] Dependency/CVE scan ...... %s\n", failStr)
	} else {
		fmt.Printf("[4/5] Dependency/CVE scan ...... %s\n", passStr)
	}

	depFindingCounter := len(allFindings) + 1
	for _, vr := range vulnResults {
		for _, v := range vr.Vulnerabilities {
			severity := determineOSVSeverity(v)

			desc := v.Summary
			if desc == "" {
				desc = v.Details
			}
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}

			fixedVersion := ""
			for _, aff := range v.Affected {
				for _, r := range aff.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed != "" {
							fixedVersion = ev.Fixed
						}
					}
				}
			}

			relFile, _ := filepath.Rel(targetScanPath, vr.SourceFile)
			if relFile == "" || strings.HasPrefix(relFile, "..") {
				relFile, _ = filepath.Rel(absPath, vr.SourceFile)
				if relFile == "" {
					relFile = vr.SourceFile
				}
			}
			relFile = filepath.ToSlash(relFile)

			recommendation := fmt.Sprintf("Update %s from %s", vr.PackageName, vr.InstalledVersion)
			if fixedVersion != "" {
				recommendation += fmt.Sprintf(" to %s or later", fixedVersion)
			}

			evidence := fmt.Sprintf("Package: %s@%s, Advisory: %s", vr.PackageName, vr.InstalledVersion, v.ID)
			if len(v.Aliases) > 0 {
				evidence += fmt.Sprintf(" (%s)", strings.Join(v.Aliases, ", "))
			}

			finding := scanner.Finding{
				ID:             fmt.Sprintf("VG-%03d", depFindingCounter),
				Category:       "dependency",
				Severity:       severity,
				Title:          fmt.Sprintf("Vulnerable Dependency: %s", vr.PackageName),
				Description:    desc,
				File:           relFile,
				Line:           0,
				Evidence:       evidence,
				Recommendation: recommendation,
				Confidence:     "HIGH",
			}
			allFindings = append(allFindings, finding)
			depFindingCounter++
		}
	}

	// Deduplicate findings
	allFindings = scanner.DeduplicateFindings(allFindings)

	// Filter baseline suppressions
	baseDir := root
	if baseDir == "" {
		baseDir = absPath
	}
	suppressions, err := baseline.LoadBaseline(baseDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Baseline Error: %v\n", err)
		if cfg.FailClosed {
			fmt.Fprintln(os.Stderr, "Security policy failure: malformed baseline and fail_closed is enabled.")
			return 3
		}
	}
	activeFindings, suppressedCount := baseline.FilterSuppressedFindings(allFindings, suppressions)
	allFindings = activeFindings

	// Calculate risk score
	var findingInfos []risk.FindingInfo
	for _, f := range allFindings {
		findingInfos = append(findingInfos, risk.FindingInfo{
			Severity: f.Severity,
		})
	}
	scoreResult := risk.CalculateScore(findingInfos)

	// Evaluate deployment gate with config policy
	blockPolicy := []string{"critical", "high"}
	if cfg != nil && len(cfg.BlockOn) > 0 {
		blockPolicy = cfg.BlockOn
	}
	gateResult := gate.EvaluateGateWithPolicy(
		scoreResult.CriticalCount,
		scoreResult.HighCount,
		scoreResult.MediumCount,
		scoreResult.LowCount,
		blockPolicy,
	)

	// Step 5: Security policy
	if gateResult.Status == "PASSED" {
		fmt.Printf("[5/5] Security policy .......... %s\n", passStr)
	} else {
		fmt.Printf("[5/5] Security policy .......... %s\n", failStr)
	}
	fmt.Println()

	// Count categories
	catCounts := report.CategoryCounts{}
	for _, f := range allFindings {
		switch strings.ToLower(f.Category) {
		case "secret":
			catCounts.Secrets++
		case "sourcecode":
			catCounts.SourceCode++
		case "dependency":
			catCounts.Dependencies++
		case "configuration":
			catCounts.Configuration++
		case "docker":
			catCounts.Docker++
		case "git":
			catCounts.Git++
		}
	}

	scanDuration := time.Since(scanStart)

	// Build the report
	r := &report.Report{
		ProjectName:     projectName,
		CommitHash:      commitHash,
		Branch:          branchName,
		Remote:          remoteURL,
		ScanTime:        scanDuration.Round(time.Millisecond).String(),
		Timestamp:       time.Now().Format("2006-01-02 15:04:05 MST"),
		FilesScanned:    scanResult.FilesScanned,
		FilesSkipped:    scanResult.FilesSkipped,
		ExcludedFiles:   scanResult.ExcludedFiles,
		SuppressedCount: suppressedCount,
		OSVMode:         osvMode,
		ScanWarnings:    scanResult.ScanWarnings,
		Findings:        allFindings,
		Dependencies:    vulnResults,
		ScoreResult:     scoreResult,
		GateResult:      gateResult,
		CategoryCounts:  catCounts,
	}

	reportsDir := "reports"
	_ = os.MkdirAll(reportsDir, 0755)

	switch strings.ToLower(format) {
	case "json":
		jsonPath := customOutput
		if jsonPath == "" {
			jsonPath = filepath.Join(reportsDir, "scan.json")
		}
		if err := report.WriteJSONReport(r, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON report: %v\n", err)
			return 2
		}
		fmt.Printf("JSON report saved to: %s\n\n", jsonPath)
		report.PrintTerminalReport(r)

	case "html":
		htmlPath := customOutput
		if htmlPath == "" {
			htmlPath = filepath.Join(reportsDir, "scan.html")
		}
		if err := report.WriteHTMLReport(r, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			return 2
		}
		fmt.Printf("HTML report saved to: %s\n\n", htmlPath)
		report.PrintTerminalReport(r)

	case "sarif":
		sarifPath := customOutput
		if sarifPath == "" {
			sarifPath = filepath.Join(reportsDir, "scan.sarif")
		}
		if err := report.WriteSarifReport(r, sarifPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SARIF report: %v\n", err)
			return 2
		}
		fmt.Printf("SARIF report saved to: %s\n\n", sarifPath)
		report.PrintTerminalReport(r)

	default:
		report.PrintTerminalReport(r)
	}

	fmt.Println()
	fmt.Println("----------------------------------------")
	fmt.Printf("Security Score: %d/100\n", scoreResult.Score)
	fmt.Println("----------------------------------------")
	fmt.Println()
	fmt.Printf("%-8s : %d\n", "Critical", scoreResult.CriticalCount)
	fmt.Printf("%-8s : %d\n", "High", scoreResult.HighCount)
	fmt.Printf("%-8s : %d\n", "Medium", scoreResult.MediumCount)
	fmt.Printf("%-8s : %d\n", "Low", scoreResult.LowCount)
	fmt.Println()

	if gateResult.Status == "PASSED" {
		fmt.Println("STATUS: SAFE TO PUSH")
		fmt.Println()

		if isHook && !isVibePush && !skipPrompt {
			ans, err := promptConsole("Proceed with Git push? [Y/N]: ")
			if err != nil {
				fmt.Println("Continuing Git push...")
				return 0
			}
			lower := strings.ToLower(ans)
			if lower == "n" || lower == "no" {
				fmt.Println("Push cancelled by user.")
				return 1
			}
			fmt.Println("Continuing Git push...")
			return 0
		}
	} else {
		fmt.Println("STATUS: PUSH BLOCKED")
		if gateResult.Reason != "" {
			fmt.Printf("Reason: %s\n", gateResult.Reason)
		}
		fmt.Println("Resolve the findings above before pushing.")
		fmt.Println("========================================")
		return gateResult.ExitCode
	}

	return gateResult.ExitCode
}
