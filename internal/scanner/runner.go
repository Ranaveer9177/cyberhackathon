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
	return RunScannerWithProgress(projectPath, nil)
}

// RunScannerWithProgress runs the Rust scanner executable with live progress support.
// If the Rust scanner is unavailable or execution fails, it falls back to the built-in Go scanner.
func RunScannerWithProgress(projectPath string, progress ScanProgressFunc) (*ScanResult, error) {
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

		cmd := exec.CommandContext(ctx, scannerExe, args...)

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
					}
				}
			}
		} else {
			output, err := cmd.Output()
			if err == nil {
				var result ScanResult
				if err := json.Unmarshal(output, &result); err == nil {
					return &result, nil
				}
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
			name:           "Potential SQL Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(fmt\.Sprintf\("SELECT|"SELECT.*"\+|query.*\+.*request|execute\("SELECT)`),
			description:    "Potential SQL injection vulnerability detected.",
			recommendation: "Use parameterized queries or prepared statements.",
		},
		{
			id:             "VG-CMD-001",
			name:           "Potential OS Command Injection",
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
			name:           "Potential TLS Misconfiguration",
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
			name:           "Potential Insecure HTTP Connection",
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
			return nil
		}

		if cfg.IsExcluded(relPath) {
			excludedCount++
			return nil
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

		// Sensitive filename checks (excluding code source files)
		if secretScan && !sourceExts[ext] && (fileName == ".env" || fileName == "id_rsa" || fileName == "id_dsa" || ext == ".pem" || ext == ".key" ||
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
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, ";") {
				continue
			}
			if strings.Contains(line, "regexp.MustCompile") || strings.Contains(line, "Regex::new") || strings.Contains(line, "Rule {") || strings.Contains(line, `strings.Contains(lineLower, "http`) || strings.Contains(line, `line_lower.contains("http`) {
				continue
			}

			for _, r := range rules {
				if r.category == "sourcecode" && !sourceExts[ext] {
					continue
				}

				isGenericAssignment := r.id == "VG-SEC-006" || r.id == "VG-SEC-007" || r.id == "VG-CRED-001"
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
					if r.id == "VG-CMD-001" {
						if strings.Contains(line, `exec.Command("git"`) || strings.Contains(line, `exec.CommandContext`) {
							continue
						}
					}

					// Skip localhost, loopback, and schemas for Insecure HTTP rule
					if r.id == "VG-HTTP-001" {
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
