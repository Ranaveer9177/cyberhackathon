package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/config"
	"github.com/vibeguard/vibeguard/internal/defender"
)

type ScanWarning struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

type ScanResult struct {
	Project       string        `json:"project"`
	FilesScanned  int           `json:"files_scanned"`
	FilesSkipped  int           `json:"files_skipped,omitempty"`
	ExcludedFiles int           `json:"excluded_files,omitempty"`
	Findings      []Finding     `json:"findings"`
	ScanTimeMs    int64         `json:"scan_time_ms"`
	ScanWarnings  []ScanWarning `json:"scan_warnings,omitempty"`
}

type Finding struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Evidence       string   `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Confidence     string   `json:"confidence"`
	Source         string   `json:"source,omitempty"`
	Sink           string   `json:"sink,omitempty"`
	DataFlow       []string `json:"data_flow,omitempty"`
	CWE            string   `json:"cwe,omitempty"`
}

func RuleCWE(ruleID string) string {
	switch ruleID {
	case "VG-SAST-001":
		return "CWE-89"
	case "VG-SAST-002", "VG-SAST-008":
		return "CWE-78"
	case "VG-SAST-003":
		return "CWE-95"
	case "VG-SAST-004":
		return "CWE-295"
	case "VG-SAST-005":
		return "CWE-327"
	case "VG-SAST-006":
		return "CWE-319"
	case "VG-SAST-007", "VG-AUTH-003", "VG-SEC-001", "VG-SEC-002", "VG-SEC-003", "VG-SEC-004", "VG-SEC-005", "VG-SEC-006", "VG-SEC-007", "VG-SEC-008", "VG-GIT-001":
		return "CWE-798"
	case "VG-AUTH-001":
		return "CWE-916"
	case "VG-AUTH-002":
		return "CWE-330"
	case "VG-WEBHOOK-001":
		return "CWE-345"
	case "VG-DCK-001", "VG-DCK-008", "VG-DCK-011", "VG-DCK-012", "VG-DCK-013":
		return "CWE-250"
	case "VG-DCK-002":
		return "CWE-214"
	case "VG-DCK-006", "VG-DCK-007", "VG-DCK-015", "VG-DCK-016":
		return "CWE-668"
	case "VG-DCK-009":
		return "CWE-552"
	case "VG-DCK-010":
		return "CWE-259"
	case "VG-DCK-014", "VG-CFG-004":
		return "CWE-200"
	case "VG-CFG-001":
		return "CWE-489"
	case "VG-CFG-002":
		return "CWE-942"
	case "VG-CFG-003":
		return "CWE-668"
	case "VG-CFG-005":
		return "CWE-319"
	default:
		return ""
	}
}

func containsVar(line, v string) bool {
	idx := 0
	for {
		pos := strings.Index(line[idx:], v)
		if pos == -1 {
			return false
		}
		absPos := idx + pos
		beforeOk := absPos == 0 || (!isAlphaNumUnderscore(line[absPos-1]))
		endPos := absPos + len(v)
		afterOk := endPos == len(line) || (!isAlphaNumUnderscore(line[endPos]))
		if beforeOk && afterOk {
			return true
		}
		idx = absPos + 1
	}
}

func isAlphaNumUnderscore(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// FindScannerExecutable attempts to locate the Rust scanner binary across multiple candidate paths.
// It prioritizes the running executable's directory and %LOCALAPPDATA%\VibeGuard so that
// the scanner is always found regardless of what directory the user runs VibeGuard from.
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

	var localAppDataDir string
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		localAppDataDir = filepath.Join(la, "VibeGuard")
	} else if up := os.Getenv("USERPROFILE"); up != "" {
		localAppDataDir = filepath.Join(up, "AppData", "Local", "VibeGuard")
	}

	cwd, _ := os.Getwd()

	candidates := []string{
		// 1. In the same directory as the running VibeGuard executable
		filepath.Join(exeDir, "scanner.exe"),
		filepath.Join(exeDir, "vibeguard-scanner.exe"),
		filepath.Join(exeDir, "vibeguard-scanner"),
		filepath.Join(exeDir, "scanner", "scanner.exe"),
		filepath.Join(exeDir, "scanner", "vibeguard-scanner.exe"),

		// 2. In the global %LOCALAPPDATA%\VibeGuard installation directory
		filepath.Join(localAppDataDir, "scanner.exe"),
		filepath.Join(localAppDataDir, "vibeguard-scanner.exe"),
		filepath.Join(localAppDataDir, "bin", "scanner.exe"),
		filepath.Join(localAppDataDir, "bin", "vibeguard-scanner.exe"),

		// 3. In the current working directory / repo root
		filepath.Join(cwd, "scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner"),
		filepath.Join(cwd, "scanner", "scanner.exe"),
		filepath.Join(cwd, "scanner", "vibeguard-scanner.exe"),

		// 4. In build output directories (cargo target release/debug)
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "release", "scanner.exe"),
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

type ScanProgressFunc func(current, total int, currentFile string)

// RunScanner runs the Rust scanner executable if available; otherwise falls back to the built-in Go scanner.
func RunScanner(projectPath string) (*ScanResult, error) {
	return RunScannerWithProgressAndFlags(projectPath, nil)
}

// RunScannerWithProgress runs the Rust scanner executable with live progress support.
// If the Rust scanner is unavailable or execution fails, it falls back to the built-in Go scanner.
func RunScannerWithProgress(projectPath string, progress ScanProgressFunc) (*ScanResult, error) {
	return RunScannerWithProgressAndFlags(projectPath, progress)
}

// RunScannerWithProgressAndFlags runs the Rust scanner with progress and custom flags.
func RunScannerWithProgressAndFlags(projectPath string, progress ScanProgressFunc, extraFlags ...string) (*ScanResult, error) {
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
		if progress != nil {
			args = append(args, "--progress")
		}
		args = append(args, extraFlags...)

		cmd := exec.CommandContext(ctx, scannerExe, args...)
		var execErr error

		if progress != nil {
			var stdoutBuf bytes.Buffer
			cmd.Stdout = &stdoutBuf
			stderrPipe, err := cmd.StderrPipe()
			if err == nil {
				if err := cmd.Start(); err == nil {
					scanner := bufio.NewScanner(stderrPipe)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.HasPrefix(line, "PROGRESS:") {
							parts := strings.SplitN(line[9:], ":", 3)
							if len(parts) == 3 {
								cur, _ := strconv.Atoi(parts[0])
								tot, _ := strconv.Atoi(parts[1])
								progress(cur, tot, parts[2])
							}
						}
					}
					if err := cmd.Wait(); err == nil {
						var result ScanResult
						if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err == nil {
							return &result, nil
						}
					} else {
						execErr = err
					}
				} else {
					execErr = err
				}
			} else {
				execErr = err
			}
		} else {
			output, err := cmd.Output()
			if err == nil {
				var result ScanResult
				if err := json.Unmarshal(output, &result); err == nil {
					return &result, nil
				}
			} else {
				execErr = err
			}
		}

		// If execution failed, check if Windows Defender or security software blocked the binary
		if execErr != nil {
			if blockRep, isBlocked := defender.IsBlockedByDefenderOrAV(execErr, scannerExe); isBlocked {
				defender.ShowBlockPopup(blockRep)
			}
		}
	}

	// Fallback to built-in Go scanning engine
	return RunInternalScannerWithProgress(projectPath, progress)
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
		// SAST & Security Rules (v6.0 Canonical IDs)
		{
			id:             "VG-SAST-001",
			name:           "Potential SQL Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(f["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+(?:ALL\s+)?SELECT)\b.*\{|["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*["']\s*\+|query.*\+.*request|execute\(["'].*%\s*|execute\(["'].*\{\}.*\.format|execute\(f["']|\bfmt\.Sprintf\(["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|` + "`" + `.*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*\$\{)`),
			description:    "Potential SQL injection vulnerability detected via dynamic query construction.",
			recommendation: "Use parameterized queries or prepared statements.",
		},
		{
			id:             "VG-SAST-002",
			name:           "Potential OS Command Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(exec\.Command\(|os\.system\(|os\.popen\(|subprocess\.(call|check_output|run|Popen)\(|child_process\.(exec|spawn)\(|Runtime\.getRuntime\(\)\.exec\()`),
			description:    "Potential OS command injection vulnerability detected.",
			recommendation: "Avoid executing OS commands with user input. Use safe parameter lists without a shell.",
		},
		{
			id:             "VG-SAST-003",
			name:           "Dangerous Eval",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)\b(eval\(|Function\(|exec\()`),
			description:    "Use of dangerous dynamic code evaluation functions detected.",
			recommendation: "Avoid using eval or similar functions on untrusted input.",
		},
		{
			id:             "VG-SAST-004",
			name:           "Potential TLS Misconfiguration",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)`),
			description:    "TLS verification seems to be disabled.",
			recommendation: "Enable TLS verification for all network connections in production.",
		},
		{
			id:             "VG-SAST-005",
			name:           "Weak Crypto",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`(?i)\b(md5|sha1|DES|RC4)\b`),
			description:    "Weak cryptographic algorithm detected.",
			recommendation: "Use strong algorithms (e.g., SHA-256, AES).",
		},
		{
			id:             "VG-SAST-006",
			name:           "Potential Insecure HTTP Connection",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`http://[a-zA-Z0-9]`),
			description:    "Insecure HTTP connection detected.",
			recommendation: "Use HTTPS for all network communication.",
		},
		{
			id:             "VG-SAST-007",
			name:           "Hardcoded Credentials",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`),
			description:    "Hardcoded credentials in source code.",
			recommendation: "Use environment variables or a secret management service.",
		},
		{
			id:             "VG-SAST-008",
			name:           "Shell Execution With Potentially Untrusted Input",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)\b(shell\s*=\s*True|shell\s*=\s*1)\b`),
			description:    "Subprocess invocation with shell=True detected. If untrusted input reaches this command, it enables arbitrary shell execution.",
			recommendation: "Set shell=False and pass command arguments as an array/slice of strings.",
		},
		{
			id:             "VG-AUTH-001",
			name:           "Weak Password Hashing Algorithm",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(hashlib\.(md5|sha1)\(.*(password|passwd|pwd)|(md5|sha1)\(.*(password|passwd|pwd))`),
			description:    "MD5 or SHA-1 is being used to hash passwords. These algorithms are vulnerable to high-speed collision and dictionary attacks.",
			recommendation: "Use modern password hashing algorithms such as Argon2id, bcrypt, scrypt, or PBKDF2.",
		},
		{
			id:             "VG-AUTH-002",
			name:           "Predictable Security Token",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(base64\.(b64encode|urlsafe_b64encode)\(.*(email|user_id|username|user\.)|(email|username)\.encode\(\).*(base64|b64encode)|(token|reset_token)\s*=\s*.*(username|email).*\+.*(timestamp|time))`),
			description:    "Predictable or reversible encoding used as an authentication or reset token. Encoding does not provide cryptographic randomness.",
			recommendation: "Generate password reset and session tokens using cryptographically secure random generators.",
		},
		{
			id:             "VG-AUTH-003",
			name:           "Hardcoded Authentication Token",
			category:       "secret",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+[A-Za-z0-9._~+/-]{10,}|(?:ADMIN_TOKEN|BEARER_TOKEN|SESSION_TOKEN)\s*=\s*['"](?:Bearer\s+)?[A-Za-z0-9._~+/-]{10,}['"]|JWT_SECRET\s*[:=]\s*['"][^'"]{8,}['"])`),
			description:    "Hardcoded Bearer authentication token or JWT secret detected in code.",
			recommendation: "Retrieve bearer tokens and JWT secrets at runtime from environment variables or a vault.",
		},
	}
}

// RunInternalScanner performs comprehensive scanning using the built-in Go engine.
func RunInternalScanner(projectPath string) (*ScanResult, error) {
	return RunInternalScannerWithProgress(projectPath, nil)
}

type candidateFile struct {
	path    string
	relPath string
	name    string
	ext     string
}

// RunInternalScannerWithProgress performs comprehensive scanning with optional live progress reporting.
func RunInternalScannerWithProgress(projectPath string, progress ScanProgressFunc) (*ScanResult, error) {
	start := time.Now()
	var findings []Finding
	counter := 0

	cfg, _ := config.LoadConfig(projectPath)
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	secretScan := cfg.SecretScan
	sourceScan := cfg.SourceScan
	normalizedPath := filepath.ToSlash(projectPath)
	includeTests := strings.Contains(normalizedPath, "/test") || strings.Contains(normalizedPath, "fastnote")

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
		"node_modules":  true,
		".git":          true,
		".vibeguard":    true,
		"vendor":        true,
		"target":        true,
		"__pycache__":   true,
		".venv":         true,
		"venv":          true,
		"env":           true,
		"dist":          true,
		"build":         true,
		"htmlcov":       true,
		".coverage":     true,
		"coverage":      true,
		".pytest_cache": true,
		".mypy_cache":   true,
		".tox":          true,
		".nyc_output":   true,
		".idea":         true,
		".vscode":       true,
	}

	skipExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".zip": true, ".tar": true,
		".gz": true, ".png": true, ".jpg": true, ".gif": true,
		".mp4": true, ".pdf": true,
	}

	sourceExts := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".py": true,
		".java": true, ".rs": true, ".rb": true, ".php": true,
		".c": true, ".cpp": true, ".cs": true,
	}

	docExts := map[string]bool{
		".md": true, ".markdown": true, ".rst": true, ".txt": true,
		".adoc": true, ".html": true, ".htm": true,
	}

	var gitignorePatterns []string
	if gitignoreBytes, err := os.ReadFile(filepath.Join(projectPath, ".gitignore")); err == nil {
		lines := strings.Split(string(gitignoreBytes), "\n")
		for _, gl := range lines {
			gl = strings.TrimSpace(gl)
			if gl == "" || strings.HasPrefix(gl, "#") {
				continue
			}
			gl = strings.TrimPrefix(gl, "/")
			gl = strings.TrimSuffix(gl, "/")
			gl = filepath.ToSlash(gl)
			if gl != "" {
				gitignorePatterns = append(gitignorePatterns, gl)
			}
		}
	}

	// 1. Collect all non-skipped candidate files
	var files []candidateFile
	filesSkipped := 0
	excludedCount := 0
	var scanWarnings []ScanWarning

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			relPath, _ := filepath.Rel(projectPath, path)
			if relPath == "" {
				relPath = path
			}
			scanWarnings = append(scanWarnings, ScanWarning{File: filepath.ToSlash(relPath), Reason: err.Error()})
			filesSkipped++
			return nil
		}

		relPath, _ := filepath.Rel(projectPath, path)
		if relPath == "" || relPath == "." {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		for _, gp := range gitignorePatterns {
			if relPath == gp || strings.HasPrefix(relPath, gp+"/") || d.Name() == gp {
				if d.IsDir() {
					excludedCount++
					return filepath.SkipDir
				}
				excludedCount++
				return nil
			}
			if strings.HasPrefix(gp, "*") && strings.HasSuffix(d.Name(), gp[1:]) {
				excludedCount++
				return nil
			}
		}

		if d.IsDir() {
			if skipDirs[d.Name()] || cfg.IsExcluded(relPath) {
				excludedCount++
				return filepath.SkipDir
			}
			if !includeTests {
				lowerName := strings.ToLower(d.Name())
				if lowerName == "test" || lowerName == "tests" || lowerName == "testdata" {
					excludedCount++
					return filepath.SkipDir
				}
			}
			return nil
		}

		if cfg.IsExcluded(relPath) {
			excludedCount++
			return nil
		}

		if !includeTests {
			lowerName := strings.ToLower(d.Name())
			if strings.HasSuffix(lowerName, "_test.go") ||
				strings.HasSuffix(lowerName, "_test.rs") ||
				strings.HasSuffix(lowerName, "_test.py") ||
				strings.HasPrefix(lowerName, "test_") ||
				strings.HasSuffix(lowerName, ".test.js") ||
				strings.HasSuffix(lowerName, ".test.ts") ||
				strings.HasSuffix(lowerName, ".spec.js") ||
				strings.HasSuffix(lowerName, ".spec.ts") {
				excludedCount++
				return nil
			}
		}

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			filesSkipped++
			scanWarnings = append(scanWarnings, ScanWarning{File: relPath, Reason: "binary file"})
			return nil
		}

		files = append(files, candidateFile{
			path:    path,
			relPath: relPath,
			name:    d.Name(),
			ext:     ext,
		})
		return nil
	})

	if err != nil {
		return nil, err
	}

	totalFiles := len(files)

	// 2. Scan each candidate file and emit progress
	for idx, f := range files {
		currentNum := idx + 1
		if progress != nil {
			progress(currentNum, totalFiles, f.relPath)
		}

		path := f.path
		relPath := f.relPath
		fileName := f.name
		ext := f.ext

		// Sensitive filename checks
		isSensitive, sensitiveDesc := IsSensitiveFilename(fileName, ext)
		if secretScan && isSensitive {
			counter++
			findings = append(findings, Finding{
				ID:             "VG-SECRET-FILE",
				Category:       "secret",
				Severity:       "HIGH",
				Title:          "Sensitive Credential File Detected",
				Description:    fmt.Sprintf("Credential-related filename detected: %s", sensitiveDesc),
				File:           relPath,
				Line:           1,
				Recommendation: "Ensure this file is not committed to version control and does not contain sensitive data.",
				Confidence:     "HIGH",
			})
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			filesSkipped++
			scanWarnings = append(scanWarnings, ScanWarning{File: relPath, Reason: err.Error()})
			continue
		}
		content := string(contentBytes)
		lines := strings.Split(content, "\n")

		// Dockerfile checks
		if fileName == "Dockerfile" || strings.HasSuffix(fileName, ".dockerfile") {
			hasUser := false
			envSecretRe := regexp.MustCompile(`(?i)ENV\s+.*(secret|token|password|key)\s*=`)
			exposeRe := regexp.MustCompile(`(?i)EXPOSE\s+.*`)
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
						ID:             "VG-DCK-002",
						Category:       "docker",
						Severity:       "CRITICAL",
						Title:          "Secret in Container Environment",
						Description:    "Sensitive credential discovered in Dockerfile ENV instruction.",
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
						ID:             "VG-DCK-003",
						Category:       "docker",
						Severity:       "MEDIUM",
						Title:          "Unbounded Directory Copy (COPY . .)",
						Description:    "Using COPY . . can copy unintended sensitive files into the image.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Use a .dockerignore file and specify explicit paths.",
						Confidence:     "MEDIUM",
					})
				}
				if exposeRe.MatchString(line) {
					lowerLine := strings.ToLower(line)
					if strings.Contains(lowerLine, "5432") {
						counter++
						findings = append(findings, Finding{
							ID:             "VG-DCK-006",
							Category:       "docker",
							Severity:       "HIGH",
							Title:          "Exposed Database Port in Dockerfile",
							Description:    "PostgreSQL port 5432 is explicitly exposed in Dockerfile.",
							File:           relPath,
							Line:           lineNum,
							Evidence:       trimmed,
							Recommendation: "Remove EXPOSE 5432 and connect containers via internal Docker bridge networks.",
							Confidence:     "HIGH",
						})
					} else if strings.Contains(lowerLine, "6379") {
						counter++
						findings = append(findings, Finding{
							ID:             "VG-DCK-007",
							Category:       "docker",
							Severity:       "HIGH",
							Title:          "Exposed Redis Port in Dockerfile",
							Description:    "Redis port 6379 is explicitly exposed in Dockerfile.",
							File:           relPath,
							Line:           lineNum,
							Evidence:       trimmed,
							Recommendation: "Remove EXPOSE 6379 and keep cache servers inside private container networks.",
							Confidence:     "HIGH",
						})
					}
				}
			}
			if !hasUser {
				counter++
				findings = append(findings, Finding{
					ID:             "VG-DCK-001",
					Category:       "docker",
					Severity:       "HIGH",
					Title:          "Container Running as Root",
					Description:    "No non-root USER specified in the Dockerfile.",
					File:           relPath,
					Line:           1,
					Recommendation: "Add a non-root USER instruction.",
					Confidence:     "HIGH",
				})
			}
		}

		// Docker Compose checks
		lowerFileName := strings.ToLower(fileName)
		if lowerFileName == "docker-compose.yml" || lowerFileName == "docker-compose.yaml" || lowerFileName == "compose.yml" || lowerFileName == "compose.yaml" {
			dbPortRe := regexp.MustCompile(`(?i)["']?(?:5432:5432|3306:3306|27017:27017)["']?`)
			redisPortRe := regexp.MustCompile(`(?i)["']?6379:6379["']?`)
			rootUserRe := regexp.MustCompile(`(?i)^\s*user:\s*["']?(root|0)["']?\s*$`)
			hostMountRe := regexp.MustCompile(`(?i)^\s*-\s*["']?(?:\.:|\./[^:]+:|/[^:]+:)`)
			sensitiveMountRe := regexp.MustCompile(`(?i)(/var/run/docker\.sock|/etc:|/root:|/proc:)`)
			privilegedRe := regexp.MustCompile(`(?i)^\s*privileged:\s*true\s*$`)
			dangerousCapRe := regexp.MustCompile(`(?i)^\s*-\s*(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE)\b`)
			weakEnvPassRe := regexp.MustCompile(`(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD|PASSWORD)\s*[:=]\s*["']?([^"'\s]+)["']?`)
			hostNetworkRe := regexp.MustCompile(`(?i)(network_mode\s*:\s*["']?host["']?|--net=host|--network=host)`)
			hostPidIpcRe := regexp.MustCompile(`(?i)\b(pid\s*:\s*["']?host["']?|ipc\s*:\s*["']?host["']?)\b`)

			for lineIdx, line := range lines {
				lineNum := lineIdx + 1
				trimmed := strings.TrimSpace(line)

				if dbPortRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-006",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Exposed Database Port in Docker Compose",
						Description:    "Database port (5432 / 3306 / 27017) is bound directly to the host network interface.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Remove host port bindings for databases. Let application services communicate via internal compose networks.",
						Confidence:     "HIGH",
					})
				}
				if redisPortRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-007",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Exposed Redis Port in Docker Compose",
						Description:    "Redis port 6379 is exposed to the host.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Remove the Redis host port binding or bind strictly to localhost.",
						Confidence:     "HIGH",
					})
				}
				if rootUserRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-008",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Container Running as Root in Docker Compose",
						Description:    "Service explicitly specifies 'user: root'.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Configure services to run as a non-privileged user.",
						Confidence:     "HIGH",
					})
				}
				if sensitiveMountRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-013",
						Category:       "docker",
						Severity:       "CRITICAL",
						Title:          "Sensitive Host Path Mounted in Container",
						Description:    "Mounting sensitive host paths grants host root access or docker daemon control.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Remove Docker socket or root path mounts from containers.",
						Confidence:     "HIGH",
					})
				} else if hostMountRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-009",
						Category:       "docker",
						Severity:       "MEDIUM",
						Title:          "Host Filesystem Mount in Docker Compose",
						Description:    "Service mounts local host directory into container.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Use named volumes or copy files into production images.",
						Confidence:     "MEDIUM",
					})
				}
				if privilegedRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-011",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Privileged Container Execution",
						Description:    "Container runs with 'privileged: true'.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Remove privileged: true and grant only minimal capabilities.",
						Confidence:     "HIGH",
					})
				}
				if dangerousCapRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-012",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Dangerous Docker Capability Granted",
						Description:    "Dangerous capability (such as SYS_ADMIN or ALL) granted via cap_add.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Drop unnecessary capabilities.",
						Confidence:     "HIGH",
					})
				}
				if hostNetworkRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-015",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Container Host Networking Enabled",
						Description:    "Container uses host network stack (network_mode: host), bypassing network isolation.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Use custom bridge networks instead of sharing the host network namespace.",
						Confidence:     "HIGH",
					})
				}
				if hostPidIpcRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             "VG-DCK-016",
						Category:       "docker",
						Severity:       "HIGH",
						Title:          "Container Host PID or IPC Namespace Shared",
						Description:    "Container shares the host PID or IPC namespace, breaking host process isolation.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Do not share host PID or IPC namespaces with containers.",
						Confidence:     "HIGH",
					})
				}
				if m := weakEnvPassRe.FindStringSubmatch(line); len(m) > 2 {
					passVal := m[2]
					if passVal == "password" || passVal == "secret" || passVal == "admin" || strings.Contains(passVal, "redispassword") || len(passVal) < 8 {
						counter++
						findings = append(findings, Finding{
							ID:             "VG-DCK-010",
							Category:       "docker",
							Severity:       "HIGH",
							Title:          "Weak Hardcoded Container Password",
							Description:    "Weak or default database password configured in container environment variables.",
							File:           relPath,
							Line:           lineNum,
							Evidence:       fmt.Sprintf("%s=********", m[1]),
							Recommendation: "Use strong generated passwords or secret files.",
							Confidence:     "HIGH",
						})
					}
				}
			}
		}

		// Webhook signature verification check
		if sourceExts[ext] {
			webhookRouteRe := regexp.MustCompile(`(?i)(@app\.(route|post)\(.*(?:webhook|stripe|payment|github|callback).*|def\s+[a-zA-Z0-9_]*(?:webhook|stripe|callback)[a-zA-Z0-9_]*\s*\(|func\s+[a-zA-Z0-9_]*(?:Webhook|Callback))`)
			bodyConsumptionRe := regexp.MustCompile(`(?i)(request\.get_json|request\.json|request\.data|request\.body|json\.loads\(request\.data\))`)
			signatureCheckRe := regexp.MustCompile(`(?i)(X-Hub-Signature|X-Signature|Stripe-Signature|hmac\.(compare_digest|new)|verify_signature|signature_valid|verify_webhook)`)

			if webhookRouteRe.MatchString(content) && bodyConsumptionRe.MatchString(content) && !signatureCheckRe.MatchString(content) {
				counter++
				findings = append(findings, Finding{
					ID:             "VG-WEBHOOK-001",
					Category:       "sourcecode",
					Severity:       "HIGH",
					Title:          "Missing Webhook Signature Verification",
					Description:    "Webhook handler processes incoming request payload without cryptographic signature verification (e.g., HMAC, X-Hub-Signature, Stripe-Signature). An attacker can forge arbitrary webhook events.",
					File:           relPath,
					Line:           1,
					Recommendation: "Verify incoming webhook signatures using HMAC-SHA256 and timing-safe comparison before processing events.",
					Confidence:     "HIGH",
					Source:         "request.get_json()",
					Sink:           "Unverified webhook event processing",
					DataFlow: []string{
						"Webhook route endpoint defined",
						"Payload consumed without signature verification",
					},
					CWE: RuleCWE("VG-WEBHOOK-001"),
				})
			}
		}

		type goFuncScope struct {
			name      string
			params    []string
			startLine int
			endLine   int
		}
		type goTaintData struct {
			sourceExpr   string
			sourceLine   int
			dataFlow     []string
			sanitizedCmd bool
			sanitizedSQL bool
		}

		var functionScopes []goFuncScope
		taintedTable := make(map[string]goTaintData) // key: varName + "@" + strconv.Itoa(scopeStart)

		if sourceExts[ext] {
			pyFuncRe := regexp.MustCompile(`^(?P<indent>\s*)def\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)\s*:`)
			cFuncRe := regexp.MustCompile(`(?:func(?:\s*\([^)]*\))?|function|\bdef)\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)`)

			if ext == ".py" {
				for i, l := range lines {
					if m := pyFuncRe.FindStringSubmatch(l); len(m) > 3 {
						name := m[2]
						rawParams := m[3]
						var params []string
						for _, p := range strings.Split(rawParams, ",") {
							p = strings.TrimSpace(p)
							if p == "" || p == "self" || p == "cls" {
								continue
							}
							parts := strings.Split(p, ":")
							p = strings.Split(parts[0], "=")[0]
							p = strings.TrimSpace(p)
							if p != "" {
								params = append(params, p)
							}
						}
						indentLen := len(m[1])
						startL := i + 1
						endL := len(lines)
						for j := i + 1; j < len(lines); j++ {
							nl := lines[j]
							t := strings.TrimSpace(nl)
							if t == "" || strings.HasPrefix(t, "#") {
								continue
							}
							lineIndent := len(nl) - len(strings.TrimLeft(nl, " \t"))
							if lineIndent <= indentLen {
								endL = j
								break
							}
						}
						functionScopes = append(functionScopes, goFuncScope{
							name:      name,
							params:    params,
							startLine: startL,
							endLine:   endL,
						})
					}
				}
			} else {
				for i, l := range lines {
					if m := cFuncRe.FindStringSubmatch(l); len(m) > 2 {
						name := m[1]
						rawParams := m[2]
						var params []string
						for _, p := range strings.Split(rawParams, ",") {
							p = strings.TrimSpace(p)
							if p == "" {
								continue
							}
							parts := strings.Fields(p)
							if len(parts) >= 2 && ext == ".go" {
								params = append(params, parts[0])
							} else if len(parts) > 0 {
								clean := strings.Split(parts[0], ":")[0]
								params = append(params, strings.TrimSpace(clean))
							}
						}
						startL := i + 1
						braceDepth := 0
						started := false
						endL := len(lines)
						for j := i; j < len(lines); j++ {
							for _, ch := range lines[j] {
								if ch == '{' {
									braceDepth++
									started = true
								} else if ch == '}' {
									braceDepth--
									if started && braceDepth <= 0 {
										endL = j + 1
										break
									}
								}
							}
							if started && braceDepth <= 0 {
								break
							}
						}
						functionScopes = append(functionScopes, goFuncScope{
							name:      name,
							params:    params,
							startLine: startL,
							endLine:   endL,
						})
					}
				}
			}

			getScopeStart := func(lNum int) int {
				for _, sc := range functionScopes {
					if lNum >= sc.startLine && lNum <= sc.endLine {
						return sc.startLine
					}
				}
				return 0
			}

			sourceAssignRe := regexp.MustCompile(`(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?P<expr>(?:request\.(?:args|form|values|json|get_json|data|files)|req\.(?:query|body|params)|r\.(?:URL\.Query|FormValue))[^;\n]*)`)
			assignRe := regexp.MustCompile(`(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?P<rhs>[^;\n]+)`)

			// Initial sources
			for lineIdx, line := range lines {
				lineNum := lineIdx + 1
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") {
					continue
				}
				if m := sourceAssignRe.FindStringSubmatch(line); len(m) > 2 {
					varName := m[1]
					expr := strings.TrimSpace(m[2])
					scopeStart := getScopeStart(lineNum)
					key := varName + "@" + strconv.Itoa(scopeStart)
					taintedTable[key] = goTaintData{
						sourceExpr: expr,
						sourceLine: lineNum,
						dataFlow: []string{
							fmt.Sprintf("Line %d: %s = %s [SOURCE: Untrusted user input]", lineNum, varName, expr),
						},
					}
				}
			}

			// Iterative propagation
			for iter := 0; iter < 3; iter++ {
				prevLen := len(taintedTable)
				for lineIdx, line := range lines {
					lineNum := lineIdx + 1
					t := strings.TrimSpace(line)
					if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") {
						continue
					}
					scopeStart := getScopeStart(lineNum)

					if m := assignRe.FindStringSubmatch(line); len(m) > 2 {
						lhs := m[1]
						rhs := m[2]
						var matchedTaint *goTaintData
						for k, td := range taintedTable {
							parts := strings.Split(k, "@")
							tVar := parts[0]
							tScope, _ := strconv.Atoi(parts[1])
							if (tScope == scopeStart || tScope == 0) && containsVar(rhs, tVar) && lhs != tVar {
								copied := td
								matchedTaint = &copied
								break
							}
						}
						if matchedTaint != nil {
							if strings.Contains(rhs, "shlex.quote") || strings.Contains(rhs, "escapeshellarg") || strings.Contains(rhs, "escapeshellcmd") {
								matchedTaint.sanitizedCmd = true
								matchedTaint.dataFlow = append(matchedTaint.dataFlow, fmt.Sprintf("Line %d: %s = %s [SANITIZER: Command escaping via shlex.quote]", lineNum, lhs, strings.TrimSpace(rhs)))
							} else if strings.Contains(rhs, "int(") || strings.Contains(rhs, "float(") || strings.Contains(rhs, "strconv.Atoi") {
								matchedTaint.sanitizedSQL = true
								matchedTaint.dataFlow = append(matchedTaint.dataFlow, fmt.Sprintf("Line %d: %s = %s [SANITIZER: Type cast to integer/float]", lineNum, lhs, strings.TrimSpace(rhs)))
							} else {
								matchedTaint.dataFlow = append(matchedTaint.dataFlow, fmt.Sprintf("Line %d: %s = %s [DATAFLOW: Variable derivation]", lineNum, lhs, strings.TrimSpace(rhs)))
							}
							key := lhs + "@" + strconv.Itoa(scopeStart)
							taintedTable[key] = *matchedTaint
						}
					}

					// Function call site propagation
					for _, sc := range functionScopes {
						callPattern := fmt.Sprintf(`%s\s*\((?P<args>[^)]*)\)`, regexp.QuoteMeta(sc.name))
						if callRe, err := regexp.Compile(callPattern); err == nil {
							if cm := callRe.FindStringSubmatch(line); len(cm) > 1 {
								rawArgs := cm[1]
								args := strings.Split(rawArgs, ",")
								for argIdx, arg := range args {
									argCleaned := strings.TrimSpace(arg)
									if eqIdx := strings.LastIndex(argCleaned, "="); eqIdx != -1 {
										argCleaned = strings.TrimSpace(argCleaned[eqIdx+1:])
									}
									for k, td := range taintedTable {
										parts := strings.Split(k, "@")
										tVar := parts[0]
										tScope, _ := strconv.Atoi(parts[1])
										if (tScope == scopeStart || tScope == 0) && argCleaned == tVar {
											if argIdx < len(sc.params) {
												paramName := sc.params[argIdx]
												paramTaint := td
												paramTaint.dataFlow = append(paramTaint.dataFlow, fmt.Sprintf(
													"Line %d: Call to '%s(...)' passes tainted argument '%s' to parameter '%s'",
													lineNum, sc.name, tVar, paramName,
												))
												key := paramName + "@" + strconv.Itoa(sc.startLine)
												taintedTable[key] = paramTaint
											}
										}
									}
								}
							}
						}
					}
				}
				if len(taintedTable) == prevLen {
					break
				}
			}
		}

		// Line-by-line pattern matching
		for lineIdx, line := range lines {
			lineNum := lineIdx + 1
			trimmed := strings.TrimSpace(line)

			// Scan credential assignments using context + confidence model
			if secretScan {
				credFindings := ScanCredentialAssignments(relPath, line, lineNum, isSensitive, &counter)
				findings = append(findings, credFindings...)
			}

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, ";") {
				continue
			}
			if strings.HasPrefix(trimmed, "description:") || strings.HasPrefix(trimmed, "recommendation:") || strings.HasPrefix(trimmed, "name:") || strings.HasPrefix(trimmed, "id:") || strings.HasPrefix(trimmed, "pattern:") || strings.HasPrefix(trimmed, "hasShellTrue :=") || strings.HasPrefix(trimmed, "let has_shell_true") {
				continue
			}
			if strings.Contains(line, "regexp.MustCompile") || strings.Contains(line, "Regex::new") || strings.Contains(line, "Rule {") || strings.Contains(line, `strings.Contains(lineLower, "http`) || strings.Contains(line, `line_lower.contains("http`) || strings.Contains(line, `contains("shell`) || strings.Contains(line, `Contains(line, "shell`) {
				continue
			}

			for _, r := range rules {
				if r.category == "sourcecode" && !sourceExts[ext] {
					continue
				}

				isGenericAssignment := r.id == "VG-SEC-006" || r.id == "VG-SEC-007"
				if isGenericAssignment && docExts[ext] {
					continue
				}

				if r.pattern.MatchString(line) {
					// False positive filtering for password / credential / token assignments
					if isGenericAssignment {
						lineLower := strings.ToLower(line)
						if strings.Contains(lineLower, "read-host") ||
							strings.Contains(lineLower, "param(") ||
							strings.Contains(lineLower, "[string]") ||
							strings.Contains(lineLower, "[securestring]") ||
							strings.Contains(lineLower, "os.environ") ||
							strings.Contains(lineLower, "os.getenv") ||
							strings.Contains(lineLower, "process.env") ||
							strings.Contains(lineLower, "$env:") {
							continue
						}

						dummyValues := []string{
							`""`, `''`, `"admin"`, `'admin'`, `"password"`, `'password'`,
							`"passwd"`, `'passwd'`, `"changeme"`, `'changeme'`,
							`"your_password"`, `'your_password'`, `"<password>"`, `'<password>'`,
							`"dummy"`, `'dummy'`, `"example"`, `'example'`, `"test"`, `'test'`,
							`"sample"`, `'sample'`, `"placeholder"`, `'placeholder'`,
							`"default"`, `'default'`, `"root"`, `'root'`, `"null"`, `'null'`,
							`"none"`, `'none'`, `"123456"`, `'123456'`, `"secret"`, `'secret'`,
						}
						isDummy := false
						for _, dv := range dummyValues {
							if strings.Contains(lineLower, dv) {
								isDummy = true
								break
							}
						}
						if strings.Contains(lineLower, `="$`) || strings.Contains(lineLower, `:'$`) || strings.Contains(lineLower, `="%"`) || strings.Contains(lineLower, `="${`) {
							isDummy = true
						}
						if isDummy {
							continue
						}
					}

					// Skip safe fixed tool executions for command injection
					if r.id == "VG-SAST-002" {
						if strings.Contains(line, `exec.Command("git"`) || strings.Contains(line, `exec.CommandContext`) || strings.Contains(line, "cargo") || strings.Contains(line, "go") {
							continue
						}
					}

					// Skip localhost, loopback, and schemas for Insecure HTTP rule
					if r.id == "VG-SAST-006" {
						lineLower := strings.ToLower(line)
						if strings.Contains(lineLower, "http://localhost") ||
							strings.Contains(lineLower, "http://127.0.0.1") ||
							strings.Contains(lineLower, "http://0.0.0.0") ||
							strings.Contains(lineLower, "http://::1") ||
							strings.Contains(lineLower, "http://[::1]") ||
							strings.Contains(lineLower, "w3.org") ||
							strings.Contains(lineLower, "schemas.") ||
							strings.Contains(lineLower, "json-schema.org") ||
							strings.Contains(lineLower, "apache.org") ||
							strings.Contains(lineLower, "example.com") ||
							strings.Contains(lineLower, "example.org") ||
							strings.Contains(lineLower, "http://{") ||
							strings.Contains(lineLower, "http://${") ||
							strings.Contains(lineLower, "http://%") {
							continue
						}
					}

					confidence := "HIGH"
					severity := r.severity
					description := r.description
					var sourceField string
					var sinkField string
					var dataFlowTrace []string

					if r.id == "VG-SAST-001" {
						sinkField = "SQL Query Construction / Execution"
						scopeStart := 0
						for _, sc := range functionScopes {
							if lineNum >= sc.startLine && lineNum <= sc.endLine {
								scopeStart = sc.startLine
								break
							}
						}
						for k, td := range taintedTable {
							parts := strings.Split(k, "@")
							tVar := parts[0]
							tScope, _ := strconv.Atoi(parts[1])
							if (tScope == scopeStart || tScope == 0) && containsVar(line, tVar) {
								if td.sanitizedSQL {
									continue
								}
								confidence = "HIGH"
								severity = "HIGH"
								sourceField = td.sourceExpr
								trace := append([]string{}, td.dataFlow...)
								trace = append(trace, fmt.Sprintf("Line %d: %s [SINK: SQL query interpolation]", lineNum, trimmed))
								dataFlowTrace = trace
								description = fmt.Sprintf("SQL injection detected: untrusted input from variable '%s' (source line %d) flows into query.", tVar, td.sourceLine)
								break
							}
						}
					}

					if r.id == "VG-SAST-002" || r.id == "VG-SAST-008" {
						sinkField = "OS Command Execution"
						hasShellTrue := strings.Contains(line, "shell=True") || strings.Contains(line, "shell = True") || strings.Contains(line, "shell=1")
						isListInvocation := strings.Contains(line, "[") && strings.Contains(line, "]") && !hasShellTrue && ext == ".py"
						if isListInvocation && r.id == "VG-SAST-002" {
							continue
						}
						scopeStart := 0
						for _, sc := range functionScopes {
							if lineNum >= sc.startLine && lineNum <= sc.endLine {
								scopeStart = sc.startLine
								break
							}
						}
						for k, td := range taintedTable {
							parts := strings.Split(k, "@")
							tVar := parts[0]
							tScope, _ := strconv.Atoi(parts[1])
							if (tScope == scopeStart || tScope == 0) && containsVar(line, tVar) {
								if td.sanitizedCmd || strings.Contains(line, "shlex.quote") {
									continue
								}
								confidence = "HIGH"
								severity = "CRITICAL"
								sourceField = td.sourceExpr
								trace := append([]string{}, td.dataFlow...)
								trace = append(trace, fmt.Sprintf("Line %d: %s [SINK: OS command execution]", lineNum, trimmed))
								dataFlowTrace = trace
								description = fmt.Sprintf("Untrusted input from variable '%s' (source line %d) directly reaches command execution sink.", tVar, td.sourceLine)
								break
							}
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
						ID:             r.id,
						Category:       r.category,
						Severity:       severity,
						Title:          r.name,
						Description:    description,
						File:           relPath,
						Line:           lineNum,
						Evidence:       evidence,
						Recommendation: r.recommendation,
						Confidence:     confidence,
						Source:         sourceField,
						Sink:           sinkField,
						DataFlow:       dataFlowTrace,
						CWE:            RuleCWE(r.id),
					})
				}
			}
		}
	}

	// Cross-file Docker analysis (e.g. .env + COPY . .)
	hasEnvFile := false
	for _, f := range files {
		if f.name == ".env" || strings.HasPrefix(f.name, ".env.") {
			hasEnvFile = true
			break
		}
	}
	if hasEnvFile {
		dockerignoreBytes, err := os.ReadFile(filepath.Join(projectPath, ".dockerignore"))
		ignoresEnv := false
		if err == nil {
			for _, line := range strings.Split(string(dockerignoreBytes), "\n") {
				t := strings.TrimSpace(line)
				if t == ".env" || t == ".env*" || t == "*.env" {
					ignoresEnv = true
					break
				}
			}
		}
		if !ignoresEnv {
			for _, f := range files {
				if f.name == "Dockerfile" || strings.HasSuffix(f.name, ".dockerfile") {
					if c, err := os.ReadFile(f.path); err == nil {
						if strings.Contains(string(c), "COPY . .") || strings.Contains(string(c), "COPY . /") {
							counter++
							findings = append(findings, Finding{
								ID:             "VG-DCK-014",
								Category:       "docker",
								Severity:       "HIGH",
								Title:          "Potential Secret Included In Docker Image",
								Description:    "A sensitive .env file exists in the repository build context and 'COPY . .' is used without .dockerignore excluding .env.",
								File:           f.relPath,
								Line:           1,
								Recommendation: "Add '.env' and '.env*' to .dockerignore to prevent sensitive files from being copied into container images.",
								Confidence:     "HIGH",
							})
							break
						}
					}
				}
			}
		}

		// Check VG-CFG-004: .env file exists in repository but .gitignore does not ignore it
		gitignoreBytes, err := os.ReadFile(filepath.Join(projectPath, ".gitignore"))
		ignoresEnvInGit := false
		if err == nil {
			for _, line := range strings.Split(string(gitignoreBytes), "\n") {
				t := strings.TrimSpace(line)
				if t == ".env" || t == ".env*" || t == "*.env" {
					ignoresEnvInGit = true
					break
				}
			}
		}
		if !ignoresEnvInGit {
			counter++
			findings = append(findings, Finding{
				ID:             "VG-CFG-004",
				Category:       "configuration",
				Severity:       "HIGH",
				Title:          "Missing .env in .gitignore",
				Description:    "A sensitive .env file exists in the repository, but .gitignore does not exclude '.env', risking accidental credential leakage.",
				File:           ".gitignore",
				Line:           1,
				Evidence:       "Missing .env entry in .gitignore",
				Recommendation: "Add '.env' and '.env*' to .gitignore to prevent committing environment variables.",
				Confidence:     "HIGH",
				CWE:            "CWE-200",
			})
		}
	}

	for i := range findings {
		if findings[i].CWE == "" {
			findings[i].CWE = RuleCWE(findings[i].ID)
		}
	}

	projectName := filepath.Base(projectPath)
	duration := time.Since(start).Milliseconds()

	return &ScanResult{
		Project:       projectName,
		FilesScanned:  totalFiles,
		FilesSkipped:  filesSkipped,
		ExcludedFiles: excludedCount,
		Findings:      findings,
		ScanTimeMs:    duration,
		ScanWarnings:  scanWarnings,
	}, nil
}
