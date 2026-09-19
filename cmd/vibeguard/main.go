package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/config"
	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/git"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/report"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const version = "3.0.0"

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
		projectPath, format, outputPath, isHook := parseScanArgs(os.Args[2:], "terminal")
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := runScan(projectPath, format, outputPath, isHook)
		os.Exit(exitCode)

	case "report":
		projectPath, format, outputPath, isHook := parseScanArgs(os.Args[2:], "html")
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

func parseScanArgs(args []string, defaultFormat string) (projectPath, format, outputPath string, isHook bool) {
	format = defaultFormat
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if (arg == "--format" || arg == "-f") && i+1 < len(args) {
			format = args[i+1]
			i++
		} else if (arg == "--output" || arg == "-o") && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		} else if arg == "--hook" {
			isHook = true
		} else if !strings.HasPrefix(arg, "-") && projectPath == "" {
			projectPath = arg
		}
	}
	return
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
	fmt.Println("  --format, -f <fmt>     Output format: terminal (default), json, html")
	fmt.Println("  --output, -o <path>    Custom report output path (default: reports/scan.json or reports/scan.html)")
	fmt.Println("  --hook                 Apply gate policy thresholds from .vibeguard/config.json")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0  PASS — Security scan passed, safe to deploy/push")
	fmt.Println("  1  BLOCK — Security policy blocked push (critical or high findings)")
	fmt.Println("  2  ERROR — Scanner or runtime error")
	fmt.Println("  3  CONFIG ERROR — Configuration file error")
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
	exitCode := runScanWithRefs(root, "terminal", "", true, explicitRefs)
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
	fmt.Println("Security scan PASSED. Code is SAFE to push.")
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

var (
	rceRegex             = regexp.MustCompile(`(?i)\b(rce|remote code execution|arbitrary code execution)\b`)
	criticalKeywordRegex = regexp.MustCompile(`(?i)\b(critical severity)\b`)
	highKeywordRegex     = regexp.MustCompile(`(?i)\b(command injection|sql injection|sqli|prototype pollution|authentication bypass|privilege escalation)\b`)
	mediumKeywordRegex   = regexp.MustCompile(`(?i)\b(cross-site scripting|xss|open redirect|directory traversal|path traversal|csrf|denial of service|dos|ssrf)\b`)
	lowKeywordRegex      = regexp.MustCompile(`(?i)\b(information disclosure|sensitive data exposure|debug information)\b`)
)

func determineOSVSeverity(v osv.Vulnerability) string {
	// 1. Check database_specific severity (e.g. GitHub Advisory GHSA severity)
	if v.DatabaseSpecific != nil {
		if rawSev, ok := v.DatabaseSpecific["severity"].(string); ok {
			switch strings.ToUpper(strings.TrimSpace(rawSev)) {
			case "CRITICAL":
				return "CRITICAL"
			case "HIGH":
				return "HIGH"
			case "MODERATE", "MEDIUM":
				return "MEDIUM"
			case "LOW":
				return "LOW"
			}
		}
	}

	// 2. Check explicit severity entries (CVSS float or CVSS vector)
	for _, s := range v.Severity {
		scoreStr := strings.ToUpper(strings.TrimSpace(s.Score))

		// Check if score is a direct float
		if val, err := strconv.ParseFloat(scoreStr, 64); err == nil {
			if val >= 9.0 {
				return "CRITICAL"
			}
			if val >= 7.0 {
				return "HIGH"
			}
			if val >= 4.0 {
				return "MEDIUM"
			}
			return "LOW"
		}

		// Check if score is a CVSS v3/v4 vector
		if strings.HasPrefix(scoreStr, "CVSS:") {
			hasNet := strings.Contains(scoreStr, "AV:N")
			hasLowComplex := strings.Contains(scoreStr, "AC:L")
			hasNoPriv := strings.Contains(scoreStr, "PR:N")
			hasNoUI := strings.Contains(scoreStr, "UI:N")
			hasAllHighImpact := strings.Contains(scoreStr, "C:H") && strings.Contains(scoreStr, "I:H") && strings.Contains(scoreStr, "A:H")

			if hasNet && hasLowComplex && hasNoPriv && hasNoUI && hasAllHighImpact {
				return "CRITICAL"
			}
			if strings.Contains(scoreStr, "C:H") || strings.Contains(scoreStr, "I:H") || strings.Contains(scoreStr, "A:H") {
				return "HIGH"
			}
			if strings.Contains(scoreStr, "C:L") || strings.Contains(scoreStr, "I:L") || strings.Contains(scoreStr, "A:L") {
				return "MEDIUM"
			}
			return "LOW"
		}

		if strings.Contains(scoreStr, "CRITICAL") {
			return "CRITICAL"
		}
		if strings.Contains(scoreStr, "HIGH") {
			return "HIGH"
		}
		if strings.Contains(scoreStr, "MEDIUM") || strings.Contains(scoreStr, "MODERATE") {
			return "MEDIUM"
		}
		if strings.Contains(scoreStr, "LOW") {
			return "LOW"
		}
	}

	// 3. Match against word boundaries in text (no substring collisions like "rce" in "source")
	combinedText := v.Summary + " " + v.Details
	if rceRegex.MatchString(combinedText) || criticalKeywordRegex.MatchString(combinedText) {
		return "CRITICAL"
	}
	if highKeywordRegex.MatchString(combinedText) {
		return "HIGH"
	}
	if mediumKeywordRegex.MatchString(combinedText) {
		return "MEDIUM"
	}
	if lowKeywordRegex.MatchString(combinedText) {
		return "LOW"
	}

	// 4. Default to MEDIUM for unclassified vulnerabilities
	return "MEDIUM"
}

func runScan(projectPath string, format string, customOutput string, isHook bool) int {
	return runScanWithRefs(projectPath, format, customOutput, isHook, nil)
}

func runScanWithRefs(projectPath string, format string, customOutput string, isHook bool, explicitRefs []git.PushRef) int {
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

		if len(pushedRefs) > 0 {
			var activeRefs []git.PushRef
			for _, pr := range pushedRefs {
				if strings.Trim(pr.LocalSHA, "0") != "" {
					activeRefs = append(activeRefs, pr)
				}
			}

			if len(activeRefs) == 0 {
				fmt.Println("Git pre-push: all pushed refs are branch deletions. Allowing push.")
				return 0
			}

			overallExitCode := 0
			failedCount := 0

			for idx, pRef := range activeRefs {
				if len(activeRefs) > 1 {
					fmt.Printf("\n========================================\n")
					fmt.Printf(" Verifying Pushed Ref [%d/%d]: %s\n", idx+1, len(activeRefs), pRef.RemoteRef)
					fmt.Printf("========================================\n")
				}

				code := scanSingleTarget(absPath, root, cfg, format, customOutput, true, &pRef)
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
					fmt.Println("Continuing Git push...")
				} else {
					fmt.Printf("STATUS: PUSH BLOCKED (%d of %d refs failed security gate)\n", failedCount, len(activeRefs))
				}
				fmt.Println("========================================")
			}

			return overallExitCode
		}
	}

	// Single target scan (CLI scan, report command, or working tree scan)
	return scanSingleTarget(absPath, absPath, cfg, format, customOutput, isHook, nil)
}

func scanSingleTarget(absPath string, root string, cfg *config.Config, format string, customOutput string, isHook bool, pRef *git.PushRef) int {
	projectName := filepath.Base(absPath)
	scanStart := time.Now()

	var commitHash, branchName, remoteURL string
	var pushedCommitDiff string
	var pushRange string
	var pushedFiles []string
	var filesInPushCount int
	var excludedFilesCount int
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

			locShort := pRef.LocalSHA
			if len(locShort) > 7 {
				locShort = locShort[:7]
			}
			remShort := pRef.RemoteSHA
			if len(remShort) > 7 {
				remShort = remShort[:7]
			}
			pushRange = fmt.Sprintf("%s -> %s", locShort, remShort)

			pushedFiles = git.GetPushedCommitFiles(root, pRef.RemoteSHA, pRef.LocalSHA)
			filesInPushCount = len(pushedFiles)
			for _, pf := range pushedFiles {
				if cfg.IsExcluded(pf) {
					excludedFilesCount++
				}
			}

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
	if isHook {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY GATE")
		fmt.Println("========================================")
		fmt.Printf("Project:        %s\n", projectName)
		if commitHash != "" {
			fmt.Printf("Commit:         %s\n", commitHash)
		}
		if branchName != "" {
			fmt.Printf("Branch:         %s\n", branchName)
		}
		if pushRange != "" {
			fmt.Printf("Push Range:     %s\n", pushRange)
		}
		if filesInPushCount > 0 {
			fmt.Printf("Files in Push:  %d (Excluded: %d)\n", filesInPushCount, excludedFilesCount)
		}
		fmt.Println()
	} else {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY SCANNER")
		fmt.Println("========================================")
		fmt.Printf("Project: %s\n", projectName)
		fmt.Printf("Path:    %s\n", absPath)
		if commitHash != "" {
			fmt.Printf("Commit:  %s\n", commitHash)
		}
		if branchName != "" {
			fmt.Printf("Branch:  %s\n", branchName)
		}
		fmt.Println()
	}

	// Step 1: Run security scanner
	fmt.Println("[1/4] Running security scanner...")
	pb := report.NewProgressBar(20, os.Stdout)
	scanResult, err := scanner.RunScannerWithProgress(targetScanPath, func(cur, tot int, curFile string) {
		pb.Render(cur, tot, fmt.Sprintf("Files: %d/%d", cur, tot), fmt.Sprintf("Current: %s", curFile))
	})
	pb.Reset()
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
	fmt.Printf("  Files scanned: %d\n", scanResult.FilesScanned)
	fmt.Printf("  Findings from scanner: %d\n", len(scanResult.Findings))

	// Step 2: Detect and check dependencies
	var vulnResults []osv.VulnResult
	if cfg.DependencyScan {
		fmt.Println("[2/4] Checking dependencies...")
		deps, err := dependencies.DetectDependencies(targetScanPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Dependency detection error: %v\n", err)
			deps = []dependencies.Dependency{}
		}
		if len(deps) > 0 {
			for idx, d := range deps {
				pb.Render(idx+1, len(deps), fmt.Sprintf("Dependencies: %d/%d", idx+1, len(deps)), fmt.Sprintf("Current: %s@%s", d.Name, d.Version))
				time.Sleep(5 * time.Millisecond)
			}
			pb.Reset()
		}
		fmt.Printf("  Dependencies found: %d\n", len(deps))

		var osvDeps []osv.DependencyInfo
		for _, d := range deps {
			osvDeps = append(osvDeps, osv.DependencyInfo{
				Name:       d.Name,
				Version:    d.Version,
				Ecosystem:  d.Ecosystem,
				SourceFile: d.SourceFile,
			})
		}

		fmt.Println("[3/4] Querying vulnerability database (OSV)...")
		var osvErr error
		vulnResults, osvErr = osv.CheckAllDependenciesWithProgress(osvDeps, func(cur, tot int) {
			pb.Render(cur, tot, fmt.Sprintf("OSV queries: %d/%d", cur, tot), "")
		})
		pb.Reset()
		if osvErr != nil && len(osvDeps) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: OSV vulnerability database unavailable: %v\n", osvErr)
			if cfg.FailClosed {
				fmt.Fprintln(os.Stderr, "Security policy failure: OSV unavailable and fail_closed is enabled.")
				return 4
			}
		}

		totalVulns := 0
		for _, vr := range vulnResults {
			totalVulns += len(vr.Vulnerabilities)
		}
		if totalVulns > 0 {
			fmt.Printf("  Vulnerable packages: %d\n", len(vulnResults))
			fmt.Printf("  Total vulnerabilities: %d\n", totalVulns)
		} else {
			fmt.Println("  No known vulnerabilities found in dependencies")
		}
	} else {
		fmt.Println("[2/4] Skipping dependency checks (disabled in config)")
		fmt.Println("[3/4] Skipping OSV lookup")
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

	// Step 4: Calculate risk score
	fmt.Println("[4/4] Calculating risk score...")
	var findingInfos []risk.FindingInfo
	for _, f := range allFindings {
		findingInfos = append(findingInfos, risk.FindingInfo{
			Severity: f.Severity,
		})
	}
	scoreResult := risk.CalculateScore(findingInfos)

	// Final Stage: scan complete indicator
	pb.Finish("Security analysis complete.")

	// Evaluate deployment gate with config policy
	blockPolicy := []string{"critical", "high"}
	if isHook && cfg != nil && len(cfg.BlockOn) > 0 {
		blockPolicy = cfg.BlockOn
	}
	gateResult := gate.EvaluateGateWithPolicy(
		scoreResult.CriticalCount,
		scoreResult.HighCount,
		scoreResult.MediumCount,
		scoreResult.LowCount,
		blockPolicy,
	)

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
		ProjectName:    projectName,
		CommitHash:     commitHash,
		Branch:         branchName,
		Remote:         remoteURL,
		ScanTime:       scanDuration.Round(time.Millisecond).String(),
		FilesScanned:   scanResult.FilesScanned,
		Findings:       allFindings,
		Dependencies:   vulnResults,
		ScoreResult:    scoreResult,
		GateResult:     gateResult,
		CategoryCounts: catCounts,
	}

	fmt.Println()

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
		fmt.Printf("JSON report saved to: %s\n", jsonPath)
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
		fmt.Printf("HTML report saved to: %s\n", htmlPath)
		report.PrintTerminalReport(r)

	default:
		report.PrintTerminalReport(r)
	}

	if isHook {
		fmt.Println("---------------------------------------------")
		if gateResult.Status == "PASSED" {
			fmt.Println("STATUS: SAFE TO PUSH")
			fmt.Println("Continuing Git push...")
		} else {
			fmt.Println("STATUS: PUSH BLOCKED")
			fmt.Printf("Reason: %s\n", gateResult.Reason)
			fmt.Println("Resolve the findings above before pushing.")
		}
		fmt.Println("========================================")
	}

	return gateResult.ExitCode
}
