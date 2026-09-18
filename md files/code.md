# VibeGuard — Complete Source Code Repository

**Project:** VibeGuard v2.0.0 (Git Secure Push Gate)  
**Generated:** 2026-09-18 23:43:51  
**Total Files:** 51  

---

## Table of Contents

1. [go.mod](#gomod)
2. [cmd/vibeguard/main.go](#cmdvibeguardmaingo)
3. [internal/config/config.go](#internalconfigconfiggo)
4. [internal/config/config_test.go](#internalconfigconfigtestgo)
5. [internal/dependencies/detector.go](#internaldependenciesdetectorgo)
6. [internal/dependencies/parser.go](#internaldependenciesparsergo)
7. [internal/dependencies/parser_test.go](#internaldependenciesparsertestgo)
8. [internal/gate/gate.go](#internalgategatego)
9. [internal/gate/gate_test.go](#internalgategatetestgo)
10. [internal/git/repo.go](#internalgitrepogo)
11. [internal/git/repo_test.go](#internalgitrepotestgo)
12. [internal/git/hooks.go](#internalgithooksgo)
13. [internal/git/hooks_test.go](#internalgithookstestgo)
14. [internal/osv/types.go](#internalosvtypesgo)
15. [internal/osv/client.go](#internalosvclientgo)
16. [internal/report/terminal.go](#internalreportterminalgo)
17. [internal/report/json.go](#internalreportjsongo)
18. [internal/report/html.go](#internalreporthtmlgo)
19. [internal/report/report_test.go](#internalreportreporttestgo)
20. [internal/risk/scorer.go](#internalriskscorergo)
21. [internal/risk/scorer_test.go](#internalriskscorertestgo)
22. [internal/scanner/runner.go](#internalscannerrunnergo)
23. [internal/scanner/runner_test.go](#internalscannerrunnertestgo)
24. [scanner/Cargo.toml](#scannercargotoml)
25. [scanner/src/main.rs](#scannersrcmainrs)
26. [scanner/src/types.rs](#scannersrctypesrs)
27. [scanner/src/scanner.rs](#scannersrcscannerrs)
28. [scanner/src/secrets.rs](#scannersrcsecretsrs)
29. [scanner/src/sast.rs](#scannersrcsastrs)
30. [scanner/src/rules.rs](#scannersrcrulesrs)
31. [scanner/src/docker.rs](#scannersrcdockerrs)
32. [scanner/src/git.rs](#scannersrcgitrs)
33. [scanner/src/config.rs](#scannersrcconfigrs)
34. [.vibeguard/config.json](#vibeguardconfigjson)
35. [test-project/Dockerfile](#testprojectdockerfile)
36. [test-project/go.mod](#testprojectgomod)
37. [test-project/package.json](#testprojectpackagejson)
38. [test-project/requirements.txt](#testprojectrequirementstxt)
39. [test-project/.env](#testprojectenv)
40. [test-project/src/config.go](#testprojectsrcconfiggo)
41. [test-project/src/database.go](#testprojectsrcdatabasego)
42. [test-project/src/auth.js](#testprojectsrcauthjs)
43. [tests/integration/integration_test.go](#testsintegrationintegrationtestgo)
44. [tests/sast/vulnerable.go](#testssastvulnerablego)
45. [tests/sast/safe.go](#testssastsafego)
46. [tests/dependencies/go.mod](#testsdependenciesgomod)
47. [tests/dependencies/package.json](#testsdependenciespackagejson)
48. [tests/dependencies/requirements.txt](#testsdependenciesrequirementstxt)
49. [tests/dependencies/Cargo.toml](#testsdependenciescargotoml)
50. [tests/secrets/fake_keys.txt](#testssecretsfakekeystxt)
51. [tests/secrets/clean_text.txt](#testssecretscleantexttxt)

---

## go.mod

``go
module github.com/vibeguard/vibeguard

go 1.21
``

---

## cmd/vibeguard/main.go

``go
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

const version = "2.0.0"

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

	// 5. Run full security scan
	fmt.Println()
	fmt.Println("Running VibeGuard security verification scan...")
	exitCode := runScan(root, "terminal", "", true)
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
		fmt.Println("Pushing to remote (git push)...")
		if err := git.GitPush(root); err != nil {
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

	projectName := filepath.Base(absPath)
	scanStart := time.Now()

	// Load configuration
	cfg, err := config.LoadConfig(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration Error: %v\n", err)
		return 3
	}

	// Git metadata if in a git repository
	var commitHash, branchName, remoteURL string
	var pushedCommitDiff string
	if git.IsGitRepo(absPath) {
		root, _ := git.FindGitRoot(absPath)
		commitHash = git.GetCommitHash(root)
		branchName = git.GetBranch(root)
		remoteURL = git.GetRemote(root)

		// When running as pre-push hook, inspect exact pushed refs from stdin
		if isHook {
			_, localSha, remoteRef, remoteSha := git.GetPushedRefs()
			if localSha != "" && localSha != "(delete)" && strings.Trim(localSha, "0") != "" {
				commitHash = localSha
				if len(commitHash) > 7 {
					commitHash = commitHash[:7]
				}
				if remoteRef != "" {
					remoteURL = remoteRef
				}
				pushedCommitDiff = git.GetPushedCommitDiff(root, remoteSha, localSha)
			}
		}
	}

	// Banner
	if isHook {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY GATE")
		fmt.Println("========================================")
		fmt.Printf("Project: %s\n", projectName)
		if commitHash != "" {
			fmt.Printf("Commit:  %s\n", commitHash)
		}
		if branchName != "" {
			fmt.Printf("Branch:  %s\n", branchName)
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
	scanResult, err := scanner.RunScanner(absPath)
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
	fmt.Printf("  Files scanned: %d\n", scanResult.FilesScanned)
	fmt.Printf("  Findings from scanner: %d\n", len(scanResult.Findings))

	// Step 2: Detect and check dependencies
	var vulnResults []osv.VulnResult
	if cfg.DependencyScan {
		fmt.Println("[2/4] Checking dependencies...")
		deps, err := dependencies.DetectDependencies(absPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Dependency detection error: %v\n", err)
			deps = []dependencies.Dependency{}
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
		vulnResults, osvErr = osv.CheckAllDependenciesWithStatus(osvDeps)
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
				parts := strings.Fields(dLine)
				if len(parts) >= 3 {
					currentFile = strings.TrimPrefix(parts[2], "a/")
				}
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

			relFile, _ := filepath.Rel(absPath, vr.SourceFile)
			if relFile == "" {
				relFile = vr.SourceFile
			}

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

	// Step 3: Calculate risk score
	fmt.Println("[4/4] Calculating risk score...")
	var findingInfos []risk.FindingInfo
	for _, f := range allFindings {
		findingInfos = append(findingInfos, risk.FindingInfo{
			Severity: f.Severity,
		})
	}
	scoreResult := risk.CalculateScore(findingInfos)

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
``

---

## internal/config/config.go

``go
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config represents VibeGuard's project-level configuration stored in .vibeguard/config.json
type Config struct {
	BlockOn        []string `json:"block_on"`        // ["critical", "high"]
	ScanMode       string   `json:"scan_mode"`       // "full" or "changed"
	DependencyScan bool     `json:"dependency_scan"`
	SecretScan     bool     `json:"secret_scan"`
	SourceScan     bool     `json:"source_scan"`
	ReportFormat   string   `json:"report_format"`   // "terminal", "json", "html"
	FailClosed     bool     `json:"fail_closed"`     // block on scanner failure
}

// DefaultConfig returns sensible default security configuration.
func DefaultConfig() *Config {
	return &Config{
		BlockOn:        []string{"critical", "high"},
		ScanMode:       "full",
		DependencyScan: true,
		SecretScan:     true,
		SourceScan:     true,
		ReportFormat:   "terminal",
		FailClosed:     true,
	}
}

// ConfigDir returns the path to the .vibeguard directory.
func ConfigDir(projectPath string) string {
	return filepath.Join(projectPath, ".vibeguard")
}

// ConfigPath returns the path to .vibeguard/config.json.
func ConfigPath(projectPath string) string {
	return filepath.Join(ConfigDir(projectPath), "config.json")
}

// LoadConfig reads .vibeguard/config.json, falling back to defaults if not found.
func LoadConfig(projectPath string) (*Config, error) {
	cfgFile := ConfigPath(projectPath)
	data, err := os.ReadFile(cfgFile)
	if os.IsNotExist(err) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// CreateDefaultConfig writes the default configuration file to .vibeguard/config.json.
func CreateDefaultConfig(projectPath string) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(DefaultConfig(), "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}

// SaveConfig writes a specific configuration to .vibeguard/config.json.
func SaveConfig(projectPath string, cfg *Config) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}
``

---

## internal/config/config_test.go

``go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.BlockOn) != 2 {
		t.Fatalf("expected 2 block_on items, got %d", len(cfg.BlockOn))
	}
	if !cfg.DependencyScan || !cfg.SecretScan || !cfg.SourceScan {
		t.Errorf("expected all scan modules enabled by default")
	}
	if !cfg.FailClosed {
		t.Errorf("expected fail_closed to be true by default")
	}
	if cfg.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", cfg.ScanMode)
	}
}

func TestCreateDefaultConfigAndLoad(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create default config file
	if err := CreateDefaultConfig(tempDir); err != nil {
		t.Fatalf("CreateDefaultConfig failed: %v", err)
	}

	// Verify file existence
	cfgFile := filepath.Join(tempDir, ".vibeguard", "config.json")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Fatalf("expected %s to exist", cfgFile)
	}

	// Load config
	loaded, err := LoadConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !loaded.FailClosed {
		t.Errorf("expected loaded fail_closed to be true")
	}
	if loaded.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", loaded.ScanMode)
	}
}
``

---

## internal/dependencies/detector.go

``go
package dependencies

import (
	"io/fs"
	"os"
	"path/filepath"
)

type Dependency struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

func DetectDependencies(projectPath string) ([]Dependency, error) {
	var deps []Dependency

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		content := string(contentBytes)

		var fileDeps []Dependency
		switch d.Name() {
		case "go.mod":
			fileDeps = ParseGoMod(content, path)
		case "package-lock.json":
			fileDeps = ParsePackageLockJSON(content, path)
		case "package.json":
			// If package-lock.json exists in same dir, prefer the lockfile for exact installed versions
			lockFile := filepath.Join(filepath.Dir(path), "package-lock.json")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParsePackageJSON(content, path)
			}
		case "requirements.txt":
			fileDeps = ParseRequirementsTxt(content, path)
		case "Cargo.lock":
			fileDeps = ParseCargoLock(content, path)
		case "Cargo.toml":
			// If Cargo.lock exists in same dir, prefer the lockfile
			lockFile := filepath.Join(filepath.Dir(path), "Cargo.lock")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParseCargoToml(content, path)
			}
		}
		deps = append(deps, fileDeps...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return deps, nil
}
``

---

## internal/dependencies/parser.go

``go
package dependencies

import (
	"encoding/json"
	"regexp"
	"strings"
)

func ParseGoMod(content string, sourceFile string) []Dependency {
	var deps []Dependency
	re := regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9.\-_/]+)\s+(v[a-zA-Z0-9.\-_+]+)(?:\s+//.*)?$`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) == 3 && match[1] != "module" && match[1] != "go" {
			deps = append(deps, Dependency{
				Name:       match[1],
				Version:    match[2],
				Ecosystem:  "Go",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

func ParsePackageJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return deps
	}

	addDeps := func(m map[string]string) {
		for name, version := range m {
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			version = strings.TrimPrefix(version, ">=")
			version = strings.TrimSpace(version)
			deps = append(deps, Dependency{
				Name:       name,
				Version:    version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}
	addDeps(pkg.Dependencies)
	addDeps(pkg.DevDependencies)
	return deps
}

func ParseRequirementsTxt(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)(?:==|>=)(.*)$`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    strings.TrimSpace(matches[2]),
				Ecosystem:  "PyPI",
				SourceFile: sourceFile,
			})
		} else {
			name := strings.Split(line, " ")[0]
			name = strings.Split(name, "=")[0]
			name = strings.Split(name, "<")[0]
			name = strings.Split(name, ">")[0]
			if name != "" && !strings.HasPrefix(name, "-") {
				deps = append(deps, Dependency{
					Name:       name,
					Version:    "unknown",
					Ecosystem:  "PyPI",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

func ParseCargoToml(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	inDeps := false
	re1 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"`)
	re2 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*\{.*version\s*=\s*"([^"]+)".*}`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDeps = strings.Contains(line, "dependencies")
			continue
		}
		if !inDeps || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if matches := re1.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		} else if matches := re2.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

// ParsePackageLockJSON parses npm package-lock.json for exact installed dependency versions.
func ParsePackageLockJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var lock struct {
		Packages     map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return deps
	}

	seen := make(map[string]bool)
	// Check npm v2/v3 packages object
	for pkgPath, info := range lock.Packages {
		if info.Version == "" {
			continue
		}
		name := strings.TrimPrefix(pkgPath, "node_modules/")
		if name != "" && name != pkgPath && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	// Check npm v1 dependencies object
	for name, info := range lock.Dependencies {
		if info.Version != "" && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	return deps
}

// ParseGoSum extracts dependency versions from go.sum.
func ParseGoSum(content string, sourceFile string) []Dependency {
	var deps []Dependency
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkg := parts[0]
			ver := strings.TrimSuffix(parts[1], "/go.mod")
			key := pkg + "@" + ver
			if !seen[key] {
				seen[key] = true
				deps = append(deps, Dependency{
					Name:       pkg,
					Version:    ver,
					Ecosystem:  "Go",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

// ParseCargoLock parses Cargo.lock for exact locked crate versions.
func ParseCargoLock(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	var currName, currVersion string
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if inPackage && currName != "" && currVersion != "" {
				deps = append(deps, Dependency{
					Name:       currName,
					Version:    currVersion,
					Ecosystem:  "crates.io",
					SourceFile: sourceFile,
				})
			}
			inPackage = true
			currName = ""
			currVersion = ""
			continue
		}
		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				currVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			}
		}
	}
	if inPackage && currName != "" && currVersion != "" {
		deps = append(deps, Dependency{
			Name:       currName,
			Version:    currVersion,
			Ecosystem:  "crates.io",
			SourceFile: sourceFile,
		})
	}
	return deps
}
``

---

## internal/dependencies/parser_test.go

``go
package dependencies

import (
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := `module example.com/app

go 1.21

require (
	golang.org/x/crypto v0.1.0
	github.com/gin-gonic/gin v1.9.0 // indirect
)
`
	deps := ParseGoMod(content, "go.mod")
	if len(deps) < 2 {
		t.Fatalf("expected at least 2 dependencies, got %d", len(deps))
	}

	foundCrypto := false
	for _, d := range deps {
		if d.Name == "golang.org/x/crypto" && d.Version == "v0.1.0" && d.Ecosystem == "Go" {
			foundCrypto = true
		}
	}
	if !foundCrypto {
		t.Errorf("expected to find golang.org/x/crypto v0.1.0")
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "~4.17.1"
  },
  "devDependencies": {
    "jest": "26.6.3"
  }
}`
	deps := ParsePackageJSON(content, "package.json")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundLodash := false
	for _, d := range deps {
		if d.Name == "lodash" && d.Version == "4.17.20" && d.Ecosystem == "npm" {
			foundLodash = true
		}
	}
	if !foundLodash {
		t.Errorf("expected to find sanitized lodash 4.17.20")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := `
# Comment
Flask==2.0.1
requests>=2.25.1
django==3.2.0
`
	deps := ParseRequirementsTxt(content, "requirements.txt")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundFlask := false
	for _, d := range deps {
		if d.Name == "Flask" && d.Version == "2.0.1" && d.Ecosystem == "PyPI" {
			foundFlask = true
		}
	}
	if !foundFlask {
		t.Errorf("expected to find Flask 2.0.1")
	}
}

func TestParseCargoToml(t *testing.T) {
	content := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0.104"
tokio = { version = "1.0", features = ["full"] }
`
	deps := ParseCargoToml(content, "Cargo.toml")
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	foundSerde := false
	for _, d := range deps {
		if d.Name == "serde" && d.Version == "1.0.104" && d.Ecosystem == "crates.io" {
			foundSerde = true
		}
	}
	if !foundSerde {
		t.Errorf("expected to find serde 1.0.104")
	}
}
``

---

## internal/gate/gate.go

``go
package gate

import (
	"fmt"
	"strings"
)

type GateResult struct {
	Status   string // "PASSED" or "BLOCKED"
	ExitCode int
	Reason   string
}

// EvaluateGate evaluates deployment status blocking on critical and high severity findings.
func EvaluateGate(criticalCount, highCount int) GateResult {
	return EvaluateGateWithPolicy(criticalCount, highCount, 0, 0, []string{"critical", "high"})
}

// EvaluateGateWithPolicy evaluates deployment status against configured blocking levels.
func EvaluateGateWithPolicy(criticalCount, highCount, mediumCount, lowCount int, blockOn []string) GateResult {
	blockMap := make(map[string]bool)
	for _, b := range blockOn {
		blockMap[strings.ToLower(strings.TrimSpace(b))] = true
	}
	if len(blockMap) == 0 {
		blockMap["critical"] = true
		blockMap["high"] = true
	}

	var blockingReasons []string
	if blockMap["critical"] && criticalCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d critical finding(s)", criticalCount))
	}
	if blockMap["high"] && highCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d high-severity finding(s)", highCount))
	}
	if blockMap["medium"] && mediumCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d medium-severity finding(s)", mediumCount))
	}
	if blockMap["low"] && lowCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d low-severity finding(s)", lowCount))
	}

	if len(blockingReasons) > 0 {
		return GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   strings.Join(blockingReasons, " and ") + " detected",
		}
	}

	return GateResult{
		Status:   "PASSED",
		ExitCode: 0,
		Reason:   "No blocking security findings",
	}
}
``

---

## internal/gate/gate_test.go

``go
package gate

import (
	"testing"
)

func TestEvaluateGate(t *testing.T) {
	tests := []struct {
		name         string
		critical     int
		high         int
		expectedStat string
		expectedCode int
	}{
		{
			name:         "High findings only -> BLOCKED",
			critical:     0,
			high:         5,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "One critical finding -> BLOCKED",
			critical:     1,
			high:         0,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Multiple critical findings -> BLOCKED",
			critical:     4,
			high:         3,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Clean scan -> PASSED",
			critical:     0,
			high:         0,
			expectedStat: "PASSED",
			expectedCode: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateGate(tc.critical, tc.high)
			if res.Status != tc.expectedStat {
				t.Errorf("expected status %s, got %s", tc.expectedStat, res.Status)
			}
			if res.ExitCode != tc.expectedCode {
				t.Errorf("expected exit code %d, got %d", tc.expectedCode, res.ExitCode)
			}
		})
	}
}

func TestEvaluateGateWithPolicy(t *testing.T) {
	// Only block on critical: high should pass
	res := EvaluateGateWithPolicy(0, 5, 2, 1, []string{"critical"})
	if res.Status != "PASSED" || res.ExitCode != 0 {
		t.Errorf("expected PASSED when blocking only on critical, got %s", res.Status)
	}

	// Block on medium: 1 medium should block
	res = EvaluateGateWithPolicy(0, 0, 1, 0, []string{"critical", "high", "medium"})
	if res.Status != "BLOCKED" || res.ExitCode != 1 {
		t.Errorf("expected BLOCKED when blocking on medium, got %s", res.Status)
	}
}
``

---

## internal/git/repo.go

``go
package git

import (
	"bufio"
	"bytes"
	"fmt"
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

// GetRemote returns the remote URL for origin.
func GetRemote(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
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

// GetPushedRefs reads standard Git pre-push ref update tuples from stdin if present.
func GetPushedRefs() (localRef, localSha, remoteRef, remoteSha string) {
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) != 0 {
		return "", "", "", ""
	}

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			return parts[0], parts[1], parts[2], parts[3]
		}
	}
	return "", "", "", ""
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
``

---

## internal/git/repo_test.go

``go
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
``

---

## internal/git/hooks.go

``go
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
``

---

## internal/git/hooks_test.go

``go
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
``

---

## internal/osv/types.go

``go
package osv

type QueryRequest struct {
	Version string  `json:"version,omitempty"`
	Package Package `json:"package"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []SeverityEntry        `json:"severity"`
	Affected         []AffectedEntry        `json:"affected"`
	References       []Reference            `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type AffectedEntry struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}
``

---

## internal/osv/client.go

``go
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DependencyInfo struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

type VulnResult struct {
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	SourceFile       string
	Vulnerabilities  []Vulnerability
}

func QueryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	reqData := QueryRequest{
		Version: version,
		Package: Package{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}
	if version == "unknown" {
		reqData.Version = ""
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	return queryResp.Vulns, nil
}

// CheckAllDependencies queries OSV for all dependencies, returning results.
func CheckAllDependencies(deps []DependencyInfo) []VulnResult {
	results, _ := CheckAllDependenciesWithStatus(deps)
	return results
}

// CheckAllDependenciesWithStatus queries OSV and returns an error if all lookups failed due to network/API outage.
func CheckAllDependenciesWithStatus(deps []DependencyInfo) ([]VulnResult, error) {
	var results []VulnResult
	var lastErr error
	successCount := 0

	ecosystemMap := map[string]string{
		"Go":        "Go",
		"npm":       "npm",
		"PyPI":      "PyPI",
		"crates.io": "crates.io",
	}

	for _, d := range deps {
		eco, ok := ecosystemMap[d.Ecosystem]
		if !ok {
			eco = d.Ecosystem
		}

		vulns, err := QueryOSV(d.Name, d.Version, eco)
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
		if len(vulns) == 0 {
			continue
		}

		results = append(results, VulnResult{
			PackageName:      d.Name,
			InstalledVersion: d.Version,
			Ecosystem:        eco,
			SourceFile:       d.SourceFile,
			Vulnerabilities:  vulns,
		})
	}

	if len(deps) > 0 && successCount == 0 && lastErr != nil {
		return results, lastErr
	}

	return results, nil
}
``

---

## internal/report/terminal.go

``go
package report

import (
	"fmt"
	"strings"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type CategoryCounts struct {
	Secrets       int
	SourceCode    int
	Dependencies  int
	Configuration int
	Docker        int
	Git           int
}

type Report struct {
	ProjectName    string
	CommitHash     string
	Branch         string
	Remote         string
	ScanTime       string
	FilesScanned   int
	Findings       []scanner.Finding
	Dependencies   []osv.VulnResult
	ScoreResult    risk.ScoreResult
	GateResult     gate.GateResult
	CategoryCounts CategoryCounts
}

func PrintTerminalReport(r *Report) {
	fmt.Println("========= VIBEGUARD SECURITY REPORT =========")
	fmt.Printf("Project: %s\n", r.ProjectName)
	if r.CommitHash != "" {
		fmt.Printf("Commit:  %s\n", r.CommitHash)
	}
	if r.Branch != "" {
		fmt.Printf("Branch:  %s\n", r.Branch)
	}
	if r.Remote != "" {
		fmt.Printf("Remote:  %s\n", r.Remote)
	}
	fmt.Printf("Scan Time: %s\n", r.ScanTime)
	fmt.Printf("Files Scanned: %d\n", r.FilesScanned)
	fmt.Println("---------------------------------------------")
	fmt.Printf("Severity Counts:\n")
	fmt.Printf("Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
		r.ScoreResult.CriticalCount,
		r.ScoreResult.HighCount,
		r.ScoreResult.MediumCount,
		r.ScoreResult.LowCount,
		r.ScoreResult.InfoCount)

	fmt.Println("---------------------------------------------")
	fmt.Printf("Category Breakdown:\n")
	fmt.Printf("Secrets: %d, Source Code: %d, Dependencies: %d, Configuration: %d, Docker: %d, Git: %d\n",
		r.CategoryCounts.Secrets, r.CategoryCounts.SourceCode, r.CategoryCounts.Dependencies,
		r.CategoryCounts.Configuration, r.CategoryCounts.Docker, r.CategoryCounts.Git)

	fmt.Println("---------------------------------------------")
	fmt.Printf("Security Score: %d/%d\n", r.ScoreResult.Score, r.ScoreResult.Total)
	
	fmt.Println("---------------------------------------------")
	fmt.Println("Findings:")
	for _, f := range r.Findings {
		color := ColorWhite
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL", "HIGH":
			color = ColorRed
		case "MEDIUM":
			color = ColorYellow
		case "LOW":
			color = ColorCyan
		case "INFO":
			color = ColorWhite
		}
		fmt.Printf("%s[%s]%s %s - %s:%d\n", color, strings.ToUpper(f.Severity), ColorReset, f.ID, f.File, f.Line)
		fmt.Printf("  Description: %s\n", f.Description)
		fmt.Printf("  Recommendation: %s\n", f.Recommendation)
	}

	fmt.Println("---------------------------------------------")
	fmt.Println("Dependency Vulnerabilities:")
	for _, d := range r.Dependencies {
		for _, v := range d.Vulnerabilities {
			fmt.Printf("%s[%s]%s %s in %s (v%s) [%s]\n", ColorRed, "VULN", ColorReset, v.ID, d.PackageName, d.InstalledVersion, d.SourceFile)
			fmt.Printf("  Summary: %s\n", v.Summary)
		}
	}

	fmt.Println("---------------------------------------------")
	statusColor := ColorGreen
	if r.GateResult.Status == "BLOCKED" {
		statusColor = ColorRed
	}
	fmt.Printf("Deployment Status: %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	fmt.Printf("Reason: %s\n", r.GateResult.Reason)
	fmt.Println("=============================================")
}
``

---

## internal/report/json.go

``go
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func WriteJSONReport(r *Report, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
``

---

## internal/report/html.go

``go
package report

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { border-bottom: 1px solid #ccc; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .score { font-size: 24px; font-weight: bold; }
        .cards { display: flex; gap: 20px; margin: 20px 0; }
        .card { flex: 1; padding: 20px; border-radius: 5px; text-align: center; font-weight: bold; }
        .card.critical { background: #ffebee; color: #c62828; }
        .card.high { background: #fff3e0; color: #ef6c00; }
        .card.medium { background: #fffde7; color: #fbc02d; }
        .card.low { background: #e0f7fa; color: #00838f; }
        .card.info { background: #eceff1; color: #455a64; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f8f8; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: #fff; }
        .badge.critical { background: #c62828; }
        .badge.high { background: #ef6c00; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #00838f; }
        .badge.info { background: #455a64; }
        .status-banner { padding: 15px; border-radius: 5px; font-weight: bold; font-size: 18px; text-align: center; }
        .status-passed { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .status-blocked { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>VibeGuard Security Report</h1>
                <p><strong>Project:</strong> {{.ProjectName}} | <strong>Scanned:</strong> {{.ScanTime}} | <strong>Files:</strong> {{.FilesScanned}}</p>
            </div>
            <div class="score">Score: {{.ScoreResult.Score}}/100</div>
        </div>

        <div class="status-banner {{if eq .GateResult.Status "PASSED"}}status-passed{{else}}status-blocked{{end}}">
            Deployment Status: {{.GateResult.Status}} - {{.GateResult.Reason}}
        </div>

        <h2>Severity Summary</h2>
        <div class="cards">
            <div class="card critical">Critical<br>{{.ScoreResult.CriticalCount}}</div>
            <div class="card high">High<br>{{.ScoreResult.HighCount}}</div>
            <div class="card medium">Medium<br>{{.ScoreResult.MediumCount}}</div>
            <div class="card low">Low<br>{{.ScoreResult.LowCount}}</div>
            <div class="card info">Info<br>{{.ScoreResult.InfoCount}}</div>
        </div>

        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Title</th>
                <th>File</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
            {{range .Findings}}
            <tr>
                <td><span class="badge {{.Severity | js}}">{{.Severity}}</span></td>
                <td>{{.ID}}</td>
                <td>{{.Title}}</td>
                <td>{{.File}}:{{.Line}}</td>
                <td>{{.Description}}</td>
                <td>{{.Recommendation}}</td>
            </tr>
            {{end}}
        </table>

        <h2>Dependency Vulnerabilities</h2>
        <table>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>Vulnerability ID</th>
                <th>Summary</th>
            </tr>
            {{range .Dependencies}}
                {{$pkg := .PackageName}}
                {{$ver := .InstalledVersion}}
                {{$eco := .Ecosystem}}
                {{range .Vulnerabilities}}
                <tr>
                    <td>{{$pkg}}</td>
                    <td>{{$ver}}</td>
                    <td>{{$eco}}</td>
                    <td>{{.ID}}</td>
                    <td>{{.Summary}}</td>
                </tr>
                {{end}}
            {{end}}
        </table>
    </div>
</body>
</html>`

func WriteHTMLReport(r *Report, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"js": func(s string) string {
			switch strings.ToUpper(s) {
			case "CRITICAL":
				return "critical"
			case "HIGH":
				return "high"
			case "MEDIUM":
				return "medium"
			case "LOW":
				return "low"
			case "INFO":
				return "info"
			default:
				return "info"
			}
		},
	}).Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}
``

---

## internal/report/report_test.go

``go
package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestReportGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_test_reports")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rep := &Report{
		ProjectName:  "TestApp",
		ScanTime:     "120ms",
		FilesScanned: 5,
		Findings: []scanner.Finding{
			{
				ID:             "VG-001",
				Category:       "secret",
				Severity:       "CRITICAL",
				Title:          "Hardcoded API Key",
				Description:    "Found exposed API key",
				File:           "config.go",
				Line:           10,
				Recommendation: "Revoke key",
				Confidence:     "HIGH",
			},
		},
		ScoreResult: risk.ScoreResult{
			Score:         85,
			Total:         100,
			CriticalCount: 1,
		},
		GateResult: gate.GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   "Critical security findings detected",
		},
		CategoryCounts: CategoryCounts{
			Secrets: 1,
		},
	}

	// Test JSON Report
	jsonPath := filepath.Join(tempDir, "scan.json")
	if err := WriteJSONReport(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Errorf("expected json report file to exist")
	}

	// Test HTML Report
	htmlPath := filepath.Join(tempDir, "scan.html")
	if err := WriteHTMLReport(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Errorf("expected html report file to exist")
	}
}
``

---

## internal/risk/scorer.go

``go
package risk

import "strings"

type FindingInfo struct {
	Severity string
}

type ScoreResult struct {
	Score         int
	Total         int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
}

func CalculateScore(findings []FindingInfo) ScoreResult {
	res := ScoreResult{
		Total: 100,
	}

	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			res.CriticalCount++
		case "HIGH":
			res.HighCount++
		case "MEDIUM":
			res.MediumCount++
		case "LOW":
			res.LowCount++
		case "INFO":
			res.InfoCount++
		}
	}

	deduction := (res.CriticalCount * 15) + (res.HighCount * 8) + (res.MediumCount * 3) + (res.LowCount * 1)
	res.Score = 100 - deduction
	if res.Score < 0 {
		res.Score = 0
	}

	return res
}
``

---

## internal/risk/scorer_test.go

``go
package risk

import (
	"testing"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name          string
		findings      []FindingInfo
		expectedScore int
		expectedCrit  int
		expectedHigh  int
	}{
		{
			name:          "Clean project",
			findings:      []FindingInfo{},
			expectedScore: 100,
			expectedCrit:  0,
			expectedHigh:  0,
		},
		{
			name: "Single critical finding",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
			},
			expectedScore: 85, // 100 - 15
			expectedCrit:  1,
			expectedHigh:  0,
		},
		{
			name: "Mixed severities",
			findings: []FindingInfo{
				{Severity: "CRITICAL"}, // -15
				{Severity: "HIGH"},     // -8
				{Severity: "MEDIUM"},   // -3
				{Severity: "LOW"},      // -1
			},
			expectedScore: 73, // 100 - 27
			expectedCrit:  1,
			expectedHigh:  1,
		},
		{
			name: "Heavily vulnerable floor at 0",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
			},
			expectedScore: 0,
			expectedCrit:  7,
			expectedHigh:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := CalculateScore(tc.findings)
			if res.Score != tc.expectedScore {
				t.Errorf("expected score %d, got %d", tc.expectedScore, res.Score)
			}
			if res.CriticalCount != tc.expectedCrit {
				t.Errorf("expected %d critical, got %d", tc.expectedCrit, res.CriticalCount)
			}
			if res.HighCount != tc.expectedHigh {
				t.Errorf("expected %d high, got %d", tc.expectedHigh, res.HighCount)
			}
		})
	}
}
``

---

## internal/scanner/runner.go

``go
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ScanResult struct {
	Project      string    `json:"project"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
	ScanTimeMs   int64     `json:"scan_time_ms"`
}

type Finding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Evidence       string `json:"evidence,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Confidence     string `json:"confidence"`
}

// FindScannerExecutable attempts to locate the Rust scanner binary across multiple candidate paths.
func FindScannerExecutable() (string, bool) {
	// 1. Explicit environment variable
	if envPath := os.Getenv("VIBEGUARD_SCANNER_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, true
		}
	}

	exePath, err := os.Executable()
	var exeDir string
	if err == nil {
		exeDir = filepath.Dir(exePath)
	}

	cwd, _ := os.Getwd()

	candidates := []string{
		// Beside the current Go binary
		filepath.Join(exeDir, "vibeguard-scanner.exe"),
		filepath.Join(exeDir, "vibeguard-scanner"),
		// In current working directory
		filepath.Join(cwd, "vibeguard-scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner"),
		// In scanner target directories
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner"),
		filepath.Join(cwd, "scanner", "target", "debug", "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "debug", "vibeguard-scanner"),
		filepath.Join(exeDir, "..", "scanner", "target", "release", "vibeguard-scanner.exe"),
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, true
		}
	}

	// In system PATH
	if path, err := exec.LookPath("vibeguard-scanner.exe"); err == nil {
		return path, true
	}
	if path, err := exec.LookPath("vibeguard-scanner"); err == nil {
		return path, true
	}

	return "", false
}

// RunScanner runs the Rust scanner executable if available; otherwise falls back to the built-in Go scanner.
func RunScanner(projectPath string) (*ScanResult, error) {
	// Read config to check enabled modules
	secretScan := true
	sourceScan := true
	cfgFile := filepath.Join(projectPath, ".vibeguard", "config.json")
	if data, err := os.ReadFile(cfgFile); err == nil {
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err == nil {
			if v, ok := raw["secret_scan"].(bool); ok {
				secretScan = v
			}
			if v, ok := raw["source_scan"].(bool); ok {
				sourceScan = v
			}
		}
	}

	scannerExe, found := FindScannerExecutable()
	if found {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		args := []string{projectPath}
		if !secretScan {
			args = append(args, "--no-secrets")
		}
		if !sourceScan {
			args = append(args, "--no-sast")
		}

		cmd := exec.CommandContext(ctx, scannerExe, args...)
		output, err := cmd.Output()
		if err == nil {
			var result ScanResult
			if err := json.Unmarshal(output, &result); err == nil {
				return &result, nil
			}
		}
	}

	// Fallback to built-in Go scanning engine
	return RunInternalScanner(projectPath)
}

// Built-in rule definition
type internalRule struct {
	id             string
	name           string
	category       string
	severity       string
	pattern        *regexp.Regexp
	description    string
	recommendation string
}

func getInternalRules() []internalRule {
	return []internalRule{
		// Secrets
		{
			id:             "VG-SEC-001",
			name:           "AWS Access Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			description:    "AWS Access Key ID detected.",
			recommendation: "Revoke the key immediately and use IAM roles instead.",
		},
		{
			id:             "VG-SEC-002",
			name:           "Generic API Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}`),
			description:    "Generic API Key detected.",
			recommendation: "Remove the key from code and use a secret manager.",
		},
		{
			id:             "VG-SEC-003",
			name:           "GitHub Token",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
			description:    "GitHub Personal Access Token detected.",
			recommendation: "Revoke the token and generate a new one if needed.",
		},
		{
			id:             "VG-SEC-004",
			name:           "Slack Token",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`xox[bprs]-[a-zA-Z0-9-]+`),
			description:    "Slack Token detected.",
			recommendation: "Revoke and rotate the Slack token.",
		},
		{
			id:             "VG-SEC-005",
			name:           "Private Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----`),
			description:    "Private cryptographic key detected.",
			recommendation: "Remove private keys from the repository.",
		},
		{
			id:             "VG-SEC-006",
			name:           "Password Assignment",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]`),
			description:    "Hardcoded password assignment detected.",
			recommendation: "Use environment variables for passwords.",
		},
		{
			id:             "VG-SEC-007",
			name:           "Token/Secret Assignment",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]`),
			description:    "Hardcoded token or secret assignment detected.",
			recommendation: "Move secrets to secure storage or environment variables.",
		},
		// SAST Rules
		{
			id:             "VG-SQL-001",
			name:           "SQL Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(fmt\.Sprintf\("SELECT|"SELECT.*"\+|query.*\+.*request|execute\("SELECT)`),
			description:    "Potential SQL injection vulnerability detected.",
			recommendation: "Use parameterized queries or prepared statements.",
		},
		{
			id:             "VG-CMD-001",
			name:           "Command Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(exec\.Command|os\.system\(|subprocess\.call\(|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()`),
			description:    "Potential OS command injection vulnerability detected.",
			recommendation: "Avoid executing OS commands with user input. Use safe APIs.",
		},
		{
			id:             "VG-EVAL-001",
			name:           "Dangerous Eval",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(eval\(|Function\(|exec\()`),
			description:    "Use of dangerous evaluation functions detected.",
			recommendation: "Avoid using eval or similar functions on untrusted input.",
		},
		{
			id:             "VG-TLS-001",
			name:           "Disabled TLS",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)`),
			description:    "TLS verification seems to be disabled.",
			recommendation: "Enable TLS verification for all network connections in production.",
		},
		{
			id:             "VG-CRYPTO-001",
			name:           "Weak Crypto",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`(?i)\b(md5|sha1|DES|RC4)\b`),
			description:    "Weak cryptographic algorithm detected.",
			recommendation: "Use strong algorithms (e.g., SHA-256, AES).",
		},
		{
			id:             "VG-HTTP-001",
			name:           "Insecure HTTP",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`http://[a-zA-Z0-9]`),
			description:    "Insecure HTTP connection detected.",
			recommendation: "Use HTTPS for all network communication.",
		},
		{
			id:             "VG-CRED-001",
			name:           "Hardcoded Credentials",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`),
			description:    "Hardcoded credentials in source code.",
			recommendation: "Use environment variables or a secret management service.",
		},
	}
}

// RunInternalScanner performs comprehensive scanning using the built-in Go engine.
func RunInternalScanner(projectPath string) (*ScanResult, error) {
	start := time.Now()
	var findings []Finding
	fileCount := 0
	counter := 0

	secretScan := true
	sourceScan := true
	cfgFile := filepath.Join(projectPath, ".vibeguard", "config.json")
	if data, err := os.ReadFile(cfgFile); err == nil {
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err == nil {
			if v, ok := raw["secret_scan"].(bool); ok {
				secretScan = v
			}
			if v, ok := raw["source_scan"].(bool); ok {
				sourceScan = v
			}
		}
	}

	allRules := getInternalRules()
	var rules []internalRule
	for _, r := range allRules {
		if r.category == "secret" && !secretScan {
			continue
		}
		if r.category == "sourcecode" && !sourceScan {
			continue
		}
		rules = append(rules, r)
	}

	skipDirs := map[string]bool{
		"node_modules": true,
		".git":         true,
		"vendor":       true,
		"target":       true,
		"__pycache__":  true,
		".venv":        true,
		"dist":         true,
		"build":        true,
	}

	skipExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".zip": true, ".tar": true,
		".gz": true, ".png": true, ".jpg": true, ".gif": true,
		".mp4": true, ".pdf": true,
	}

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		fileCount++
		relPath, _ := filepath.Rel(projectPath, path)
		if relPath == "" {
			relPath = path
		}

		fileName := d.Name()

		// Sensitive filename checks
		if secretScan && (fileName == ".env" || fileName == "id_rsa" || fileName == "id_dsa" || ext == ".pem" || ext == ".key" ||
			strings.HasPrefix(fileName, "credentials.") || strings.HasPrefix(fileName, "secrets.")) {
			counter++
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("VG-%03d", counter),
				Category:       "secret",
				Severity:       "CRITICAL",
				Title:          "Sensitive File Detected",
				Description:    "A file commonly used to store secrets or credentials was found.",
				File:           relPath,
				Line:           1,
				Recommendation: "Ensure this file is not committed to version control and does not contain sensitive data.",
				Confidence:     "HIGH",
			})
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(contentBytes)
		lines := strings.Split(content, "\n")

		// Dockerfile checks
		if fileName == "Dockerfile" || strings.HasSuffix(fileName, ".dockerfile") {
			hasUser := false
			envSecretRe := regexp.MustCompile(`(?i)ENV\s+.*(secret|token|password|key)\s*=`)
			for lineIdx, line := range lines {
				lineNum := lineIdx + 1
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "USER ") {
					u := strings.TrimSpace(strings.TrimPrefix(trimmed, "USER "))
					if u != "root" && u != "0" {
						hasUser = true
					}
				}
				if envSecretRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       "docker",
						Severity:       "CRITICAL",
						Title:          "Secrets in ENV",
						Description:    "Environment variables in Dockerfiles can expose secrets.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Avoid setting sensitive data in ENV. Use runtime secrets.",
						Confidence:     "HIGH",
					})
				}
				if strings.Contains(trimmed, "COPY . .") {
					counter++
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       "docker",
						Severity:       "MEDIUM",
						Title:          "COPY . . without caution",
						Description:    "Using COPY . . can copy unintended sensitive files into the image.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Use a .dockerignore file and specify explicit paths.",
						Confidence:     "MEDIUM",
					})
				}
			}
			if !hasUser {
				counter++
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("VG-%03d", counter),
					Category:       "docker",
					Severity:       "HIGH",
					Title:          "Running as root",
					Description:    "No non-root USER specified in the Dockerfile.",
					File:           relPath,
					Line:           1,
					Recommendation: "Add a non-root USER instruction.",
					Confidence:     "HIGH",
				})
			}
		}

		// Line-by-line pattern matching
		for lineIdx, line := range lines {
			lineNum := lineIdx + 1
			for _, r := range rules {
				if r.pattern.MatchString(line) {
					// Skip localhost/loopback for Insecure HTTP rule
					if r.id == "VG-HTTP-001" {
						if strings.Contains(line, "http://localhost") || strings.Contains(line, "http://127.0.0.1") {
							continue
						}
					}
					counter++
					evidence := strings.TrimSpace(line)
					if r.category == "secret" {
						if len(evidence) > 8 {
							evidence = evidence[:8] + "****"
						} else {
							evidence = "****"
						}
					}

					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       r.category,
						Severity:       r.severity,
						Title:          r.name,
						Description:    r.description,
						File:           relPath,
						Line:           lineNum,
						Evidence:       evidence,
						Recommendation: r.recommendation,
						Confidence:     "HIGH",
					})
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	projectName := filepath.Base(projectPath)
	duration := time.Since(start).Milliseconds()

	return &ScanResult{
		Project:      projectName,
		FilesScanned: fileCount,
		Findings:     findings,
		ScanTimeMs:   duration,
	}, nil
}
``

---

## internal/scanner/runner_test.go

``go
package scanner

import (
	"path/filepath"
	"testing"
)

func TestInternalScannerOnTestProject(t *testing.T) {
	testProjDir, err := filepath.Abs("../../test-project")
	if err != nil {
		t.Fatalf("failed to resolve test-project path: %v", err)
	}

	result, err := RunInternalScanner(testProjDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Errorf("expected files to be scanned, got 0")
	}

	if len(result.Findings) == 0 {
		t.Errorf("expected findings in vulnerable test-project, got 0")
	}

	foundSecret := false
	foundSQL := false
	foundDocker := false

	for _, f := range result.Findings {
		if f.Category == "secret" {
			foundSecret = true
		}
		if f.Title == "SQL Injection" {
			foundSQL = true
		}
		if f.Category == "docker" {
			foundDocker = true
		}
	}

	if !foundSecret {
		t.Errorf("expected at least one secret finding in test-project")
	}
	if !foundSQL {
		t.Errorf("expected SQL injection finding in test-project")
	}
	if !foundDocker {
		t.Errorf("expected docker finding in test-project")
	}
}
``

---

## scanner/Cargo.toml

``toml
[package]
name = "vibeguard-scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
walkdir = "2"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
``

---

## scanner/src/main.rs

``rust
mod config;
mod docker;
mod git;
mod rules;
mod sast;
mod scanner;
mod secrets;
mod types;

use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::json;
use types::ScanResult;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "{}",
            json!({ "error": "Usage: vibeguard-scanner <project_path> [--no-secrets] [--no-sast]" })
        );
        std::process::exit(2);
    }

    let project_path = &args[1];
    let start_time = Instant::now();

    // Check CLI flags
    let cli_no_secrets = args.iter().any(|a| a == "--no-secrets");
    let cli_no_sast = args.iter().any(|a| a == "--no-sast");

    // Check .vibeguard/config.json if present
    let mut enable_secrets = !cli_no_secrets;
    let mut enable_sast = !cli_no_sast;

    let cfg_file = Path::new(project_path).join(".vibeguard").join("config.json");
    if let Ok(cfg_data) = fs::read_to_string(&cfg_file) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cfg_data) {
            if let Some(sec) = parsed.get("secret_scan").and_then(|v| v.as_bool()) {
                if !sec {
                    enable_secrets = false;
                }
            }
            if let Some(src) = parsed.get("source_scan").and_then(|v| v.as_bool()) {
                if !src {
                    enable_sast = false;
                }
            }
        }
    }

    let files = scanner::scan_directory(project_path);
    let mut all_findings = Vec::new();
    let mut finding_counter = 0;

    for file_path in &files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip files that can't be read as string (e.g. binary)
        };

        if enable_secrets {
            let mut findings = secrets::scan_secrets(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        if enable_sast {
            let mut findings = sast::scan_source_code(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if filename == "Dockerfile" || filename.ends_with(".dockerfile") {
            let mut docker_findings = docker::scan_dockerfile(file_path, &content, &mut finding_counter);
            all_findings.append(&mut docker_findings);
        }

        let config_exts = ["yaml", "yml", "toml", "ini", "conf", "cfg", "json"];
        if config_exts.contains(&ext) || filename.starts_with("config.") {
            let mut config_findings = config::scan_config(file_path, &content, &mut finding_counter);
            all_findings.append(&mut config_findings);
        }
    }

    if enable_secrets {
        let mut git_findings = git::scan_git_security(&files, &mut finding_counter);
        all_findings.append(&mut git_findings);
    }

    let project_name = Path::new(project_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let duration = start_time.elapsed().as_millis() as u64;

    let result = ScanResult {
        project: project_name,
        files_scanned: files.len(),
        findings: all_findings,
        scan_time_ms: duration,
    };

    match serde_json::to_string(&result) {
        Ok(json_out) => println!("{}", json_out),
        Err(e) => {
            eprintln!("{}", json!({ "error": format!("Serialization failed: {}", e) }));
            std::process::exit(2);
        }
    }
}
``

---

## scanner/src/types.rs

``rust
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
    SourceCode,
    Dependency,
    Configuration,
    Docker,
    Git,
    File,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub evidence: Option<String>,
    pub recommendation: Option<String>,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub project: String,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub scan_time_ms: u64,
}
``

---

## scanner/src/scanner.rs

``rust
use std::path::Path;
use walkdir::WalkDir;

pub fn scan_directory(path: &str) -> Vec<String> {
    let mut files = Vec::new();

    let skipped_dirs = [
        "node_modules", "vendor", ".git", "target", "__pycache__", ".venv", "dist", "build",
    ];

    let skipped_exts = [
        "exe", "dll", "so", "dylib", "bin", "dat", "zip", "tar", "gz", "png", "jpg", "gif", "mp4",
        "pdf",
    ];

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();
        
        let mut skip = false;
        for component in file_path.components() {
            if let Some(comp_str) = component.as_os_str().to_str() {
                if skipped_dirs.contains(&comp_str) {
                    skip = true;
                    break;
                }
            }
        }
        
        if let Some(ext) = file_path.extension().and_then(|s| s.to_str()) {
            if skipped_exts.contains(&ext) {
                skip = true;
            }
        }
        
        if !skip {
            if let Some(path_str) = file_path.to_str() {
                files.push(path_str.to_string());
            }
        }
    }
    
    files
}
``

---

## scanner/src/secrets.rs

``rust
use crate::types::{Category, Finding, Severity};
use crate::rules::get_secret_rules;

pub fn scan_secrets(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_secret_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        for rule in &rules {
            if let Some(caps) = rule.pattern.captures(line) {
                *finding_counter += 1;
                
                let mut evidence = caps.get(0).map_or("", |m| m.as_str()).to_string();
                if evidence.len() > 8 {
                    evidence = format!("{}****", &evidence[..8]);
                } else {
                    evidence = "****".to_string();
                }

                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Secret,
                    severity: Severity::CRITICAL,
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(evidence),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "HIGH".to_string(),
                });
            }
        }
    }

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let bad_filenames = [".env", "id_rsa", "id_dsa", ".htpasswd"];
    let bad_exts = ["pem", "key"];

    let mut is_bad_file = bad_filenames.contains(&file_name) || file_name.starts_with("credentials.") || file_name.starts_with("secrets.");
    
    if !is_bad_file {
        if let Some(ext) = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()) {
            if bad_exts.contains(&ext) {
                is_bad_file = true;
            }
        }
    }

    if is_bad_file && findings.is_empty() {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "Sensitive File Detected".to_string(),
            description: "A file commonly used to store secrets or credentials was found.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Ensure this file is not committed to version control and does not contain sensitive data.".to_string()),
            confidence: "HIGH".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_key() {
        let mut counter = 0;
        let content = "aws_key = AKIA1234567890ABCDEF\n";
        let findings = scan_secrets("config.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "AWS Access Key");
        assert_eq!(counter, 1);
        assert!(findings[0].evidence.as_ref().unwrap().contains("****"));
    }

    #[test]
    fn test_clean_file_no_secrets() {
        let mut counter = 0;
        let content = "let username = \"john_doe\";\nlet port = 8080;\n";
        let findings = scan_secrets("main.rs", content, &mut counter);
        assert!(findings.is_empty());
        assert_eq!(counter, 0);
    }
}
``

---

## scanner/src/sast.rs

``rust
use crate::types::{Category, Finding};
use crate::rules::get_sast_rules;
use std::path::Path;

pub fn scan_source_code(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let ext = Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let allowed_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];
    if !allowed_exts.contains(&ext) {
        return findings;
    }

    let rules = get_sast_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        for rule in &rules {
            if rule.pattern.is_match(line) {
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::SourceCode,
                    severity: rule.severity.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "MEDIUM".to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sql_injection() {
        let mut counter = 0;
        let content = "let q = fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", input);\n";
        let findings = scan_source_code("db.go", content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "SQL Injection");
    }

    #[test]
    fn test_ignore_unsupported_extensions() {
        let mut counter = 0;
        let content = "fmt.Sprintf(\"SELECT * FROM users\")";
        let findings = scan_source_code("readme.md", content, &mut counter);
        assert!(findings.is_empty());
    }
}
``

---

## scanner/src/rules.rs

``rust
use crate::types::{Category, Severity};
use regex::Regex;

pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern: Regex,
    pub description: String,
    pub recommendation: String,
}

pub fn get_sast_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SAST-001".to_string(),
            name: "SQL Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(fmt\.Sprintf\("SELECT|"SELECT.*"\+|query.*\+.*request|execute\("SELECT)"#).unwrap(),
            description: "Potential SQL injection vulnerability detected.".to_string(),
            recommendation: "Use parameterized queries or prepared statements.".to_string(),
        },
        Rule {
            id: "SAST-002".to_string(),
            name: "Command Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(exec\.Command|os\.system\(|subprocess\.call\(|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()"#).unwrap(),
            description: "Potential OS command injection vulnerability detected.".to_string(),
            recommendation: "Avoid executing OS commands with user input. Use safe APIs.".to_string(),
        },
        Rule {
            id: "SAST-003".to_string(),
            name: "Dangerous Eval".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(eval\(|Function\(|exec\()"#).unwrap(),
            description: "Use of dangerous evaluation functions detected.".to_string(),
            recommendation: "Avoid using eval or similar functions on untrusted input.".to_string(),
        },
        Rule {
            id: "SAST-004".to_string(),
            name: "Disabled TLS".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)"#).unwrap(),
            description: "TLS verification seems to be disabled.".to_string(),
            recommendation: "Enable TLS verification for all network connections in production.".to_string(),
        },
        Rule {
            id: "SAST-005".to_string(),
            name: "Weak Crypto".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"(?i)\b(md5|sha1|DES|RC4|Math\.random\(\))\b"#).unwrap(),
            description: "Weak cryptographic algorithm or PRNG detected.".to_string(),
            recommendation: "Use strong algorithms (e.g., SHA-256, AES) and secure PRNGs.".to_string(),
        },
        Rule {
            id: "SAST-006".to_string(),
            name: "Insecure HTTP".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"http://(?!localhost|127\.0\.0\.1)"#).unwrap(),
            description: "Insecure HTTP connection detected.".to_string(),
            recommendation: "Use HTTPS for all network communication.".to_string(),
        },
        Rule {
            id: "SAST-007".to_string(),
            name: "Hardcoded Credentials".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)password\s*=\s*"[^"]+""#).unwrap(),
            description: "Hardcoded credentials in source code.".to_string(),
            recommendation: "Use environment variables or a secret management service.".to_string(),
        },
    ]
}

pub fn get_secret_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SEC-001".to_string(),
            name: "AWS Access Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
            description: "AWS Access Key ID detected.".to_string(),
            recommendation: "Revoke the key immediately and use IAM roles instead.".to_string(),
        },
        Rule {
            id: "SEC-002".to_string(),
            name: "Generic API Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}"#).unwrap(),
            description: "Generic API Key detected.".to_string(),
            recommendation: "Remove the key from code and use a secret manager.".to_string(),
        },
        Rule {
            id: "SEC-003".to_string(),
            name: "GitHub Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(),
            description: "GitHub Personal Access Token detected.".to_string(),
            recommendation: "Revoke the token and generate a new one if needed.".to_string(),
        },
        Rule {
            id: "SEC-004".to_string(),
            name: "Slack Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"xox[bprs]-[a-zA-Z0-9-]+"#).unwrap(),
            description: "Slack Token detected.".to_string(),
            recommendation: "Revoke and rotate the Slack token.".to_string(),
        },
        Rule {
            id: "SEC-005".to_string(),
            name: "Private Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----"#).unwrap(),
            description: "Private cryptographic key detected.".to_string(),
            recommendation: "Remove private keys from the repository.".to_string(),
        },
        Rule {
            id: "SEC-006".to_string(),
            name: "Password Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]"#).unwrap(),
            description: "Hardcoded password assignment detected.".to_string(),
            recommendation: "Use environment variables for passwords.".to_string(),
        },
        Rule {
            id: "SEC-007".to_string(),
            name: "Token/Secret Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
            description: "Hardcoded token or secret assignment detected.".to_string(),
            recommendation: "Move secrets to secure storage or environment variables.".to_string(),
        },
        Rule {
            id: "SEC-008".to_string(),
            name: "Generic Credential".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(secret|credential)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
            description: "Generic secret or credential detected.".to_string(),
            recommendation: "Securely manage all credentials outside of source control.".to_string(),
        },
    ]
}
``

---

## scanner/src/docker.rs

``rust
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_dockerfile(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let mut has_user = false;
    let mut uses_latest = false;
    let mut has_healthcheck = false;

    let env_secret_re = Regex::new(r#"(?i)ENV\s+.*(secret|token|password|key)\s*="#).unwrap();
    let copy_all_re = Regex::new(r#"COPY\s+\.\s+\."#).unwrap();
    let expose_re = Regex::new(r#"EXPOSE\s+.*"#).unwrap();
    let from_latest_re = Regex::new(r#"(?i)FROM\s+.*:latest"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if line.trim().starts_with("USER ") {
            let user = line.trim().replace("USER ", "").trim().to_string();
            if user != "root" && user != "0" {
                has_user = true;
            }
        }
        
        if line.trim().starts_with("HEALTHCHECK") {
            has_healthcheck = true;
        }

        if env_secret_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Secrets in ENV".to_string(),
                description: "Environment variables in Dockerfiles can expose secrets.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Avoid setting sensitive data in ENV. Use runtime secrets.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if copy_all_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "COPY . . without caution".to_string(),
                description: "Using COPY . . can copy unintended sensitive files into the image.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use a .dockerignore file and specify explicit paths.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if expose_re.is_match(line) {
            let ports = line.split_whitespace().count() - 1;
            if ports > 3 {
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Docker,
                    severity: Severity::LOW,
                    title: "Privileged/Many port exposure".to_string(),
                    description: "Exposing many ports could increase the attack surface.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some("Only EXPOSE necessary ports.".to_string()),
                    confidence: "LOW".to_string(),
                });
            }
        }
        
        if from_latest_re.is_match(line) {
            uses_latest = true;
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Using latest tag".to_string(),
                description: "Base image is using the 'latest' tag.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Pin base images to specific versions.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
    }
    
    if !has_user {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::HIGH,
            title: "Running as root".to_string(),
            description: "No non-root USER specified in the Dockerfile.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a non-root USER instruction.".to_string()),
            confidence: "HIGH".to_string(),
        });
    }
    
    if !has_healthcheck {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::LOW,
            title: "Missing HEALTHCHECK".to_string(),
            description: "No HEALTHCHECK instruction defined.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a HEALTHCHECK to ensure the container is running correctly.".to_string()),
            confidence: "MEDIUM".to_string(),
        });
    }

    findings
}
``

---

## scanner/src/git.rs

``rust
use crate::types::{Category, Finding, Severity};
use std::path::Path;

pub fn scan_git_security(scanned_files: &[String], finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file_path in scanned_files {
        let file_name = Path::new(file_path).file_name().and_then(|n| n.to_str()).unwrap_or("");
        
        let bad_files = [".env", "id_rsa", "id_dsa", ".htpasswd"];
        let is_bad = bad_files.contains(&file_name) 
            || file_name.starts_with("credentials.") 
            || file_name.ends_with(".pem");
            
        if is_bad {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Git,
                severity: Severity::CRITICAL,
                title: "Sensitive File Tracked".to_string(),
                description: "A potentially sensitive file is present in the repository structure.".to_string(),
                file: file_path.clone(),
                line: 1,
                evidence: Some(file_name.to_string()),
                recommendation: Some("Add this file to .gitignore and remove it from tracking if necessary.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
    }
    
    findings
}
``

---

## scanner/src/config.rs

``rust
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_config(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let debug_re = Regex::new(r#"(?i)(debug.*true|DEBUG.*=.*1)"#).unwrap();
    let cors_re = Regex::new(r#"(?i)Access-Control-Allow-Origin.*\*"#).unwrap();
    let bind_re = Regex::new(r#"0\.0\.0\.0"#).unwrap();
    let http_re = Regex::new(r#"(?i)(endpoint|url).*http://"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if debug_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Debug Mode Enabled".to_string(),
                description: "Debug mode appears to be enabled in configuration.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Disable debug mode in production environments.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if cors_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Wildcard CORS Allowed".to_string(),
                description: "CORS is configured to allow all origins (*).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Restrict CORS origins to trusted domains.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if bind_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::LOW,
                title: "Binding to 0.0.0.0".to_string(),
                description: "Service is bound to all network interfaces (0.0.0.0).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Ensure binding to 0.0.0.0 is intentional and properly firewalled.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if http_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Plain HTTP Endpoint".to_string(),
                description: "Configuration uses plain HTTP URLs.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use HTTPS for all endpoints.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
    }

    findings
}
``

---

## .vibeguard/config.json

``json
{
  "block_on": [
    "critical",
    "high"
  ],
  "scan_mode": "full",
  "dependency_scan": true,
  "secret_scan": true,
  "source_scan": true,
  "report_format": "terminal",
  "fail_closed": true
}
``

---

## test-project/Dockerfile

``dockerfile
FROM node:latest

WORKDIR /app

ENV DATABASE_URL=postgresql://admin:password123@db:5432/production
ENV API_SECRET=hardcoded-secret-in-dockerfile
ENV NODE_ENV=production

COPY . .

RUN npm install

EXPOSE 3000
EXPOSE 8080
EXPOSE 5432

CMD ["node", "server.js"]
``

---

## test-project/go.mod

``go
module github.com/demo/demoshop

go 1.21

require (
	golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b
	golang.org/x/text v0.3.7
)
``

---

## test-project/package.json

``json
{
  "name": "demoshop-frontend",
  "version": "1.0.0",
  "description": "Demo Shop Frontend - Deliberately Vulnerable",
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.17.1",
    "jsonwebtoken": "8.5.1",
    "axios": "0.21.1"
  },
  "devDependencies": {
    "nodemon": "2.0.7"
  }
}
``

---

## test-project/requirements.txt

``text
Flask==2.0.1
requests==2.25.1
PyJWT==2.3.0
cryptography==3.4.8
Django==3.2.0
``

---

## test-project/.env

``sh
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=SuperSecret123!
DB_NAME=production_db

# API Keys
API_KEY=sk-demo-1234567890abcdef1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# JWT
JWT_SECRET=my-super-secret-jwt-key-that-should-not-be-here

# Stripe
STRIPE_SECRET_KEY=sk_test_fake1234567890abcdefghijklmnop
``

---

## test-project/src/config.go

``go
package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// Application configuration
var (
	APIKey      = "sk-demo-1234567890abcdef1234567890abcdef"
	DatabaseURL = "postgresql://admin:password123@localhost:5432/mydb"
	JWTSecret   = "my-hardcoded-jwt-secret-key"
	DebugMode   = true
)

func ConnectToAPI() {
	// Disabled TLS verification - INSECURE
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Using insecure HTTP
	resp, err := client.Get("http://api.example.com/data")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
}

func GetPassword() string {
	password := "admin123"
	return password
}
``

---

## test-project/src/database.go

``go
package database

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

var db *sql.DB

// SQL Injection vulnerability
func GetUser(username string) (*sql.Row, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	row := db.QueryRow(query)
	return row, nil
}

// Another SQL injection
func SearchProducts(term string) (*sql.Rows, error) {
	query := "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
	return db.Query(query)
}

// Command injection vulnerability
func RunDiagnostics(host string) ([]byte, error) {
	cmd := exec.Command("ping", host)
	return cmd.Output()
}

// Weak cryptography
func HashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Another weak hash
func GenerateToken(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}
``

---

## test-project/src/auth.js

``javascript
const jwt = require('jsonwebtoken');
const http = require('http');
const { exec } = require('child_process');

// Hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-do-not-share';
const API_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// Dangerous eval usage
function processUserInput(input) {
    const result = eval(input);
    return result;
}

// Another dangerous eval
function computeFormula(formula) {
    return new Function('return ' + formula)();
}

// Command injection
function checkServer(hostname) {
    exec('ping -c 4 ' + hostname, (error, stdout) => {
        console.log(stdout);
    });
}

// Insecure HTTP request
function fetchData() {
    return fetch('http://api.payment-gateway.com/process');
}

// Weak crypto
const crypto = require('crypto');
function hashData(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

module.exports = { processUserInput, checkServer, fetchData, hashData };
``

---

## tests/integration/integration_test.go

``go
package integration

import (
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
)

func TestEndToEndDependencyDetection(t *testing.T) {
	// Test against the fixtures in tests/dependencies
	fixtureDir, err := filepath.Abs("../dependencies")
	if err != nil {
		t.Fatalf("failed to get fixture path: %v", err)
	}

	deps, err := dependencies.DetectDependencies(fixtureDir)
	if err != nil {
		t.Fatalf("DetectDependencies returned error: %v", err)
	}

	if len(deps) == 0 {
		t.Errorf("expected dependencies to be discovered in fixture dir, got 0")
	}

	// Verify risk score calculation with mock findings
	mockFindings := []risk.FindingInfo{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
	}
	score := risk.CalculateScore(mockFindings)
	gateRes := gate.EvaluateGate(score.CriticalCount, score.HighCount)

	if gateRes.Status != "BLOCKED" || gateRes.ExitCode != 1 {
		t.Errorf("expected gate to BLOCK with exit code 1, got %s (%d)", gateRes.Status, gateRes.ExitCode)
	}
}
``

---

## tests/sast/vulnerable.go

``go
package sample

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
)

func VulnerableOperations(userInput string) {
	// SQL Injection pattern
	_ = fmt.Sprintf("SELECT * FROM accounts WHERE id = '%s'", userInput)

	// Command injection pattern
	_ = exec.Command("sh", "-c", userInput)

	// Disabled TLS verification
	_ = &tls.Config{InsecureSkipVerify: true}

	// Insecure HTTP
	_, _ = http.Get("http://insecure-api.internal/endpoint")

	// Weak Crypto
	_ = md5.Sum([]byte(userInput))
}
``

---

## tests/sast/safe.go

``go
package sample

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"net/http"
)

func SafeOperations(db *sql.DB, userInput string) {
	// Parameterized SQL query
	_ = db.QueryRow("SELECT * FROM accounts WHERE id = ?", userInput)

	// Secure TLS
	_ = &tls.Config{InsecureSkipVerify: false}

	// HTTPS endpoint
	_, _ = http.Get("https://secure-api.internal/endpoint")

	// Strong Crypto
	_ = sha256.Sum256([]byte(userInput))
}
``

---

## tests/dependencies/go.mod

``go
module test/deps

go 1.21

require (
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	github.com/gin-gonic/gin v1.6.3
)
``

---

## tests/dependencies/package.json

``json
{
  "name": "test-deps",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.15",
    "minimist": "1.2.0"
  },
  "devDependencies": {
    "mocha": "^8.0.1"
  }
}
``

---

## tests/dependencies/requirements.txt

``text
# Python dependencies fixture
flask==1.1.2
jinja2==2.11.2
requests>=2.20.0
# Comment line
werkzeug==1.0.1
``

---

## tests/dependencies/Cargo.toml

``toml
[package]
name = "test-deps"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.100"
regex = "1.4.0"
tokio = { version = "1.0.0", features = ["full"] }
``

---

## tests/secrets/fake_keys.txt

``text
# Test fixtures for secret detection
AWS_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_examplefakegithubtokenplaceholder00
GENERIC_API_KEY="api_key = 'abcdef1234567890abcdef1234567890'"
PASSWORD_ASSIGN="password = 'SuperSecretTestPassword!'"
SLACK_TOKEN="xoxb-mock-slack-test-token-not-real"
``

---

## tests/secrets/clean_text.txt

``text
This is a standard text file with no credentials, secrets, or API keys.
It is used to verify that the scanner produces 0 false positives on clean files.
public_key_name = "guest"
account_type = "free"
welcome_message = "Hello, World!"
``

---

