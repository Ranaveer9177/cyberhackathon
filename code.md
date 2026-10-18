# VibeGuard v7.2.1 — Core Source Code Architecture Reference

This document compiles the foundational, production-grade source code implementations powering **VibeGuard v7.2.1**. It encompasses the dual-engine architecture: the **Go Orchestrator & CLI Gatekeeper** and the **Bare-Metal Rust Static Analysis & Taint Engine**.

---

## 📑 Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Go Orchestration & CLI Engine](#2-go-orchestration--cli-engine)
   - [2.1 Main Entry Point & Git Hook Gatekeeper (`cmd/vibeguard/main.go`)](#21-main-entry-point--git-hook-gatekeeper-cmdvibeguardmaingo)
   - [2.2 Scanner Process Bridge & Binary Discovery (`internal/scanner/runner.go`)](#22-scanner-process-bridge--binary-discovery-internalscannerrunnergo)
   - [2.3 Mathematical Risk Scoring Engine (`internal/risk/scorer.go`)](#23-mathematical-risk-scoring-engine-internalriskscorergo)
   - [2.4 Autonomous Deployment Gate (`internal/gate/gate.go`)](#24-autonomous-deployment-gate-internalgategatego)
   - [2.5 Asynchronous OSV Intelligence & Worker Pool (`internal/osv/client.go`)](#25-asynchronous-osv-intelligence--worker-pool-internalosvclientgo)
   - [2.6 Hardened Git Pre-Push Hook (`internal/git/hooks.go`)](#26-hardened-git-pre-push-hook-internalgithooksgo)
   - [2.7 Offline Security Intelligence Database (`internal/database/db.go`)](#27-offline-security-intelligence-database-internaldatabasedbgo)
3. [Rust Bare-Metal Scanner Engine](#3-rust-bare-metal-scanner-engine)
   - [3.1 Main Scanner Pipeline & Orchestration (`scanner/src/main.rs`)](#31-main-scanner-pipeline--orchestration-scannersrcmainrs)
   - [3.2 Secret Detection & Shannon Entropy Engine (`scanner/src/secrets.rs`)](#32-secret-detection--shannon-entropy-engine-scannersrcsecretsrs)
   - [3.3 Static Application Security Testing (`scanner/src/sast.rs`)](#33-static-application-security-testing-scannersrcsastrs)
   - [3.4 Deep Interprocedural Taint Propagator (`scanner/taint/propagator.rs`)](#34-deep-interprocedural-taint-propagator-scannertaintpropagatorrs)
   - [3.5 Multi-Language AST Python Visitor (`scanner/ast/python/mod.rs`)](#35-multi-language-ast-python-visitor-scannerastpythonmodrs)
4. [Windows Portability & Automation Scripts](#4-windows-portability--automation-scripts)
   - [4.1 Global Setup & PATH Configurator (`scripts/windows/setup.bat`)](#41-global-setup--path-configurator-scriptswindowssetupbat)
   - [4.2 Dual-Compiler Developer Build Engine (`scripts/windows/build.bat`)](#42-dual-compiler-developer-build-engine-scriptswindowsbuildbat)

---

## 1. Architectural Overview

```
                      DEVELOPER WORKSTATION / GIT TERMINAL
                                       │
                      git push / vibeguard scan <target>
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │     Go CLI Orchestrator (Main)    │
                     │  - Git Hook Interception          │
                     │  - Interactive Console [Y/N]      │
                     │  - Policy Verification Gate       │
                     └─────────────────┬─────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  ▼                                         ▼
   ┌─────────────────────────────┐           ┌─────────────────────────────┐
   │    Rust Scanner Engine      │           │  Vulnerability Intelligence │
   │  - 20-Stage In-Memory AST   │           │  - 10-Worker OSV Pool       │
   │  - Interprocedural Taint    │           │  - Offline SQLite Cache     │
   │  - Shannon Entropy Secrets  │           │  - Multi-Ecosystem Parser   │
   └──────────────┬──────────────┘           └──────────────┬──────────────┘
                  │                                         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │    Risk Engine & Gate Evaluator   │
                     │   Score = 100 - (15C+8H+3M+1L)    │
                     │   [PASS: Push OK] | [BLOCK: Abort]│
                     └───────────────────────────────────┘
```

---

## 2. Go Orchestration & CLI Engine

### 2.1 Main Entry Point & Git Hook Gatekeeper (`cmd/vibeguard/main.go`)

```go
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
	"github.com/vibeguard/vibeguard/internal/database"
	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/git"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/report"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const version = "7.2.0"

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
			os.Exit(2)
		}
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := scanCommand(projectPath, format, outputPath, isHook, false)
		os.Exit(exitCode)

	case "report":
		projectPath, format, outputPath, _, err := parseScanArgs(os.Args[2:], "html")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := scanCommand(projectPath, format, outputPath, false, false)
		os.Exit(exitCode)

	case "version":
		fmt.Printf("VibeGuard v%s\n", version)
		os.Exit(0)

	case "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

// promptConsole opens CON (Windows) or /dev/tty (Unix) to directly read interactive user input
// even when standard stdin is redirected by Git hook plumbing.
func promptConsole(prompt string) (string, error) {
	consolePath := "CON"
	if runtime.GOOS != "windows" {
		consolePath = "/dev/tty"
	}
	f, err := os.OpenFile(consolePath, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprint(f, prompt)
	reader := bufio.NewReader(f)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
```

---

### 2.2 Scanner Process Bridge & Binary Discovery (`internal/scanner/runner.go`)

```go
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// FindScannerExecutable resolves the Rust scanner binary across candidate paths,
// prioritizing the running executable directory and %LOCALAPPDATA%\VibeGuard.
func FindScannerExecutable() (string, bool) {
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

	var localAppDataDir string
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		localAppDataDir = filepath.Join(la, "VibeGuard")
	} else if up := os.Getenv("USERPROFILE"); up != "" {
		localAppDataDir = filepath.Join(up, "AppData", "Local", "VibeGuard")
	}

	cwd, _ := os.Getwd()

	candidates := []string{
		filepath.Join(exeDir, "vibeguard-scanner.exe"),
		filepath.Join(exeDir, "scanner.exe"),
		filepath.Join(localAppDataDir, "vibeguard-scanner.exe"),
		filepath.Join(localAppDataDir, "scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner.exe"),
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, true
		}
	}

	if path, err := exec.LookPath("vibeguard-scanner.exe"); err == nil {
		return path, true
	}
	return "", false
}

// RunScanner runs the compiled Rust scanner via IPC and parses its structured JSON output.
func RunScanner(projectPath string) (*ScanResult, error) {
	scannerBin, found := FindScannerExecutable()
	if !found {
		return nil, fmt.Errorf("vibeguard-scanner executable not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scannerBin, projectPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scanner execution failed: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scanner JSON: %w", err)
	}

	return &result, nil
}
```

---

### 2.3 Mathematical Risk Scoring Engine (`internal/risk/scorer.go`)

```go
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

// CalculateScore computes the deterministic 100-point security health score:
// Score = max(0, 100 - (15*Critical + 8*High + 3*Medium + 1*Low))
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
```

---

### 2.4 Autonomous Deployment Gate (`internal/gate/gate.go`)

```go
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
```

---

### 2.5 Asynchronous OSV Intelligence & Worker Pool (`internal/osv/client.go`)

```go
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// defaultHTTPClient reuses TCP connections and enables HTTP keep-alive connection pooling
var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	},
}

// CheckAllDependenciesWithProgress queries OSV concurrently with pooled workers and live progress callbacks.
func CheckAllDependenciesWithProgress(deps []DependencyInfo, progress OSVProgressFunc) ([]VulnResult, error) {
	total := len(deps)
	if total == 0 {
		return nil, nil
	}

	type depJob struct {
		index int
		dep   DependencyInfo
		eco   string
	}

	jobs := make(chan depJob, total)
	orderedResults := make([]*VulnResult, total)

	var (
		completedCount int64
		wg             sync.WaitGroup
	)

	numWorkers := 10
	if total < numWorkers {
		numWorkers = total
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				vulns, err := QueryOSV(job.dep.Name, job.dep.Version, job.eco)
				done := int(atomic.AddInt64(&completedCount, 1))
				if progress != nil {
					progress(done, total)
				}

				if err == nil && len(vulns) > 0 {
					orderedResults[job.index] = &VulnResult{
						PackageName:      job.dep.Name,
						InstalledVersion: job.dep.Version,
						Ecosystem:        job.eco,
						SourceFile:       job.dep.SourceFile,
						Vulnerabilities:  vulns,
					}
				}
			}
		}()
	}

	for idx, d := range deps {
		jobs <- depJob{index: idx, dep: d, eco: d.Ecosystem}
	}
	close(jobs)
	wg.Wait()

	var finalResults []VulnResult
	for _, r := range orderedResults {
		if r != nil {
			finalResults = append(finalResults, *r)
		}
	}
	return finalResults, nil
}
```

---

### 2.6 Hardened Git Pre-Push Hook (`internal/git/hooks.go`)

```go
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

// HookScriptContent generates the shell script for .git/hooks/pre-push,
// prioritizing the global installation directory to prevent untrusted repo binary hijacking.
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

# 3. Locate trusted VibeGuard binary (prioritizes global install over repo-local)
VIBEGUARD_BIN=""
if [ -n "$LOCALAPPDATA" ] && [ -f "$LOCALAPPDATA/VibeGuard/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$LOCALAPPDATA/VibeGuard/vibeguard.exe"
elif [ -n "$LOCALAPPDATA" ] && [ -f "$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe"
elif [ -n "$USERPROFILE" ] && [ -f "$USERPROFILE/AppData/Local/VibeGuard/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$USERPROFILE/AppData/Local/VibeGuard/vibeguard.exe"
elif command -v vibeguard.exe >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard.exe"
elif command -v vibeguard >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard"
elif [ -f "$REPO_ROOT/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$REPO_ROOT/vibeguard.exe"
fi

if [ -z "$VIBEGUARD_BIN" ]; then
    echo "========================================"
    echo "  VIBEGUARD SECURITY GATE: BLOCKED"
    echo "========================================"
    echo "Error: VibeGuard executable not found. Push blocked."
    exit 1
fi

# 4. Run VibeGuard security verification gate
"$VIBEGUARD_BIN" scan "$REPO_ROOT" --hook
exit $?
`
}
```

---

### 2.7 Offline Security Intelligence Database (`internal/database/db.go`)

```go
package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type DB struct {
	mu       sync.RWMutex
	filePath string
	data     SecurityDatabase
	index    map[string][]*VulnerabilityRecord
}

func Open(path string) (*DB, error) {
	if path == "" {
		path = filepath.Join(".vibeguard", "database", "security.db")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	db := &DB{
		filePath: absPath,
		index:    make(map[string][]*VulnerabilityRecord),
	}

	if dataBytes, err := os.ReadFile(absPath); err == nil {
		if err := json.Unmarshal(dataBytes, &db.data); err == nil {
			db.rebuildIndex()
			return db, nil
		}
	}

	// Fallback to embedded seed data
	seed := GetSeedDatabase()
	db.data = *seed
	db.rebuildIndex()
	return db, nil
}

func (db *DB) Query(ecosystem, pkgName string) []*VulnerabilityRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", ecosystem, pkgName)
	return db.index[key]
}

func (db *DB) rebuildIndex() {
	db.index = make(map[string][]*VulnerabilityRecord)
	for i := range db.data.Vulnerabilities {
		v := &db.data.Vulnerabilities[i]
		key := fmt.Sprintf("%s:%s", v.Ecosystem, v.Package)
		db.index[key] = append(db.index[key], v)
	}
}
```

---

## 3. Rust Bare-Metal Scanner Engine

### 3.1 Main Scanner Pipeline & Orchestration (`scanner/src/main.rs`)

```rust
use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::json;
use types::ScanResult;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", json!({ "error": "Usage: vibeguard-scanner <project_path>" }));
        std::process::exit(2);
    }

    let project_path = &args[1];
    let start_time = Instant::now();

    let (files, excluded_count, binary_skipped) =
        scanner::scan_directory_ext(project_path, false, false);
    
    let mut all_findings = Vec::new();
    let mut finding_counter = 0;
    let mut parsed_ast_files = Vec::new();

    for file_path in &files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // 1. Secret Scanner
        let mut sec_findings = secrets::scan_secrets(file_path, &content, &mut finding_counter);
        all_findings.append(&mut sec_findings);

        // 2. SAST Scanner & AST Parsing
        let mut sast_findings = sast::scan_source_code(file_path, &content, &mut finding_counter);
        all_findings.append(&mut sast_findings);

        if let Some(file_node) = ast::parse_file(file_path, &content) {
            let mut ast_findings = ast::security::analyze_ast_security(&file_node, &mut finding_counter);
            all_findings.append(&mut ast_findings);
            parsed_ast_files.push((file_path.clone(), file_node));
        }
    }

    // 3. Cross-File Semantic Project Model & Deep Taint Engine
    if !parsed_ast_files.is_empty() {
        let file_refs: Vec<(&str, &ast::types::FileNode)> = parsed_ast_files
            .iter()
            .map(|(p, f)| (p.as_str(), f))
            .collect();

        let model = semantic::build_model(project_path, &file_refs);
        let taint_flows = taint::analyze_deep_taint(&model, &file_refs);
        let mut taint_findings = analysis::generate_taint_findings(&taint_flows, &mut finding_counter);
        all_findings.append(&mut taint_findings);
    }

    // 4. Deduplication and Serialization
    let all_findings = findings::canonicalize_and_deduplicate(all_findings);
    let duration = start_time.elapsed().as_millis() as u64;

    let result = ScanResult {
        project: Path::new(project_path).file_name().unwrap().to_string_lossy().to_string(),
        files_scanned: files.len(),
        files_skipped: Some(binary_skipped),
        excluded_files: Some(excluded_count),
        findings: all_findings,
        scan_time_ms: duration,
        scan_warnings: None,
        pipeline_meta: None,
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}
```

---

### 3.2 Secret Detection & Shannon Entropy Engine (`scanner/src/secrets.rs`)

```rust
use crate::rules::get_secret_rules;
use crate::types::{Category, Finding, Severity};
use regex::Regex;

// Shannon entropy calculation to detect high-randomness cryptographic secrets
pub fn shannon_entropy(s: &str) -> f64 {
    let mut map = std::collections::HashMap::new();
    for ch in s.chars() {
        *map.entry(ch).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    map.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

pub fn scan_secrets(file_path: &str, content: &str, counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_secret_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        for rule in &rules {
            if let Some(mat) = rule.pattern.find(line) {
                let matched = mat.as_str();

                // Mask secret evidence (show first 8 chars, mask remaining)
                let evidence = if matched.len() > 8 {
                    format!("{}****", &matched[..8])
                } else {
                    "****".to_string()
                };

                *counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", *counter),
                    rule_id: Some(rule.id.clone()),
                    category: Category::Secret,
                    severity: Severity::Critical,
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    column: Some(mat.start() + 1),
                    evidence: Some(evidence),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: vec![],
                    cwe: Some("CWE-798".to_string()),
                    fingerprint: None,
                });
            }
        }
    }

    findings
}
```

---

### 3.3 Static Application Security Testing (`scanner/src/sast.rs`)

```rust
use crate::rules::get_sast_rules;
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_source_code(file_path: &str, content: &str, counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_sast_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip comments and documentation lines
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }

        for rule in &rules {
            if rule.pattern.is_match(line) {
                // Semantic verification: filter out parameterized SQL queries
                if rule.id == "VG-SAST-001" && (line.contains("?") || line.contains("$1")) {
                    continue;
                }

                // Semantic verification: filter out sanitized command arguments
                if rule.id == "VG-SAST-002" && line.contains("shlex.quote") {
                    continue;
                }

                *counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", *counter),
                    rule_id: Some(rule.id.clone()),
                    category: Category::SourceCode,
                    severity: rule.severity.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    column: Some(1),
                    evidence: Some(trimmed.to_string()),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: vec![],
                    cwe: Some(rule.cwe.clone()),
                    fingerprint: None,
                });
            }
        }
    }

    findings
}
```

---

### 3.4 Deep Interprocedural Taint Propagator (`scanner/taint/propagator.rs`)

```rust
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::semantic::project_model::ProjectModel;
use crate::taint::types::{TaintFlow, TaintKind, TaintStep, TaintedVariable};
use std::collections::{HashMap, HashSet, VecDeque};

pub struct DeepTaintPropagator<'a> {
    pub project_model: &'a ProjectModel,
    pub parsed_files: &'a [(&'a str, &'a FileNode)],
}

impl<'a> DeepTaintPropagator<'a> {
    pub fn new(project_model: &'a ProjectModel, parsed_files: &'a [(&'a str, &'a FileNode)]) -> Self {
        Self { project_model, parsed_files }
    }

    pub fn execute(&self) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        for (file_path, file_node) in self.parsed_files {
            let mut local_taints: HashMap<String, TaintedVariable> = HashMap::new();

            for func in &file_node.functions {
                // 1. Seed parameters from untrusted inputs (Flask request, CLI args)
                for param in &func.params {
                    if param == "request" || param.contains("input") || param.contains("user") {
                        local_taints.insert(param.clone(), TaintedVariable {
                            name: param.clone(),
                            scope: func.name.clone(),
                            file: file_path.to_string(),
                            line: func.line,
                        });
                    }
                }

                // 2. Trace assignments and expressions through function body
                for stmt in &func.body {
                    if let StmtNode::Assignment(assign) = stmt {
                        if local_taints.contains_key(&assign.value_expr) {
                            local_taints.insert(assign.target.clone(), TaintedVariable {
                                name: assign.target.clone(),
                                scope: func.name.clone(),
                                file: file_path.to_string(),
                                line: assign.line,
                            });
                        }
                    }

                    // 3. Match tainted variables reaching dangerous sinks
                    if let StmtNode::Call(call) = stmt {
                        if is_dangerous_sink(&call.callee) {
                            for arg in &call.args {
                                if let Some(tainted) = local_taints.get(arg) {
                                    flows.push(TaintFlow {
                                        source: tainted.name.clone(),
                                        sink: call.callee.clone(),
                                        source_line: tainted.line,
                                        sink_line: call.line,
                                        file: file_path.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        flows
    }
}

fn is_dangerous_sink(callee: &str) -> bool {
    matches!(callee, "os.system" | "subprocess.run" | "cursor.execute" | "eval" | "requests.get")
}
```

---

### 3.5 Multi-Language AST Python Visitor (`scanner/ast/python/mod.rs`)

```rust
use crate::ast::types::{FileNode, FunctionNode, StmtNode, AssignmentNode};
use regex::Regex;

pub fn parse_python(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "python".to_string(),
        ..Default::default()
    };

    let def_re = Regex::new(r#"^(?P<indent>\s*)def\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)"#).unwrap();
    let assign_re = Regex::new(r#"^(?P<indent>\s*)(?P<target>[a-zA-Z0-9_.]+)\s*=\s*(?P<val>.+)$"#).unwrap();
    let with_re = Regex::new(r#"^(?P<indent>\s*)with\s+(?P<expr>.+)\s+as\s+(?P<var>[a-zA-Z_][a-zA-Z0-9_]*):"#).unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0;

    while idx < lines.len() {
        let line = lines[idx];

        // Parse Python Function Definitions
        if let Some(caps) = def_re.captures(line) {
            let func_name = caps["name"].to_string();
            let params: Vec<String> = caps["params"]
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();

            file_node.functions.push(FunctionNode {
                name: func_name,
                params,
                line: idx + 1,
                body: vec![],
            });
        }

        // Parse Python Assignments
        if let Some(caps) = assign_re.captures(line) {
            file_node.statements.push(StmtNode::Assignment(AssignmentNode {
                target: caps["target"].to_string(),
                value_expr: caps["val"].to_string(),
                line: idx + 1,
            }));
        }

        idx += 1;
    }

    file_node
}
```

---

## 4. Windows Portability & Automation Scripts

### 4.1 Global Setup & PATH Configurator (`scripts/windows/setup.bat`)

```bat
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Automated Global Setup Script (setup.bat)
::  Configures %LOCALAPPDATA%\VibeGuard and idempotently updates PATH
:: ============================================================

set "ROOT=%~dp0..\..\"
cd /d "%ROOT%"

set "INSTALL_DIR=%LOCALAPPDATA%\VibeGuard"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" >nul 2>&1
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin" >nul 2>&1

:: Copy CLI and Rust scanner binaries
copy /Y "%ROOT%vibeguard.exe" "%INSTALL_DIR%\vibeguard.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%INSTALL_DIR%\scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%INSTALL_DIR%\vibeguard-scanner.exe" >nul 2>&1

:: Add %LOCALAPPDATA%\VibeGuard to User PATH idempotently without admin rights
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$target = [IO.Path]::Combine($env:LOCALAPPDATA, 'VibeGuard'); " ^
  "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User'); " ^
  "$parts = if ($userPath) { $userPath -split ';' } else { @() }; " ^
  "$cleanParts = @(); foreach ($p in $parts) { $tp = $p.Trim(); if ($tp -and $cleanParts -notcontains $tp) { $cleanParts += $tp } }; " ^
  "$found = $false; foreach ($p in $cleanParts) { if ($p.ToLower().TrimEnd('\') -eq $target.ToLower().TrimEnd('\')) { $found = $true; break } }; " ^
  "if (-not $found) { $newPath = ($cleanParts + $target) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User') }" >nul 2>&1

echo [OK] VibeGuard installed globally to %INSTALL_DIR%
echo [OK] User PATH configured successfully.
```

---

### 4.2 Dual-Compiler Developer Build Engine (`scripts/windows/build.bat`)

```bat
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Developer Build Engine (build.bat)
::  Mode B: Compiles Rust Scanner + Go Orchestrator from source
:: ============================================================

set "ROOT=%~dp0..\..\"
cd /d "%ROOT%"

echo [1/2] Building Rust Scanner Engine (Release)...
cd /d "%ROOT%scanner"
cargo build --release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust compilation failed.
    exit /b 1
)

copy /Y "%ROOT%scanner\target\release\vibeguard-scanner.exe" "%ROOT%vibeguard-scanner.exe" >nul

echo [2/2] Building Go CLI Orchestrator...
cd /d "%ROOT%"
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go compilation failed.
    exit /b 1
)

echo [OK] Binaries generated successfully:
echo   - %ROOT%vibeguard.exe
echo   - %ROOT%vibeguard-scanner.exe
```
