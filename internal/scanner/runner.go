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

	"github.com/vibeguard/vibeguard/internal/config"
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
	start := time.Now()
	var findings []Finding
	fileCount := 0
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

	sourceExts := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".py": true,
		".java": true, ".rs": true, ".rb": true, ".php": true,
		".c": true, ".cpp": true, ".cs": true,
	}

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(projectPath, path)
		if relPath == "" || relPath == "." {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		if d.IsDir() {
			if skipDirs[d.Name()] || cfg.IsExcluded(relPath) {
				return filepath.SkipDir
			}
			return nil
		}

		if cfg.IsExcluded(relPath) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		fileCount++
		fileName := d.Name()

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
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if strings.Contains(line, "regexp.MustCompile") || strings.Contains(line, "Regex::new") || strings.Contains(line, "Rule {") {
				continue
			}

			for _, r := range rules {
				if r.category == "sourcecode" && !sourceExts[ext] {
					continue
				}

				if r.pattern.MatchString(line) {
					// Skip safe fixed tool executions for command injection
					if r.id == "VG-CMD-001" {
						if strings.Contains(line, `exec.Command("git"`) || strings.Contains(line, `exec.CommandContext`) {
							continue
						}
					}

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
