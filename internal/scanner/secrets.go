package scanner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var assignRegex = regexp.MustCompile(`(?i)(?:^|[\s,;{(])(?P<key>[a-zA-Z0-9_-]*(?:password|passwd|pwd|api[_-]?key|apikey|jwt[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)[a-zA-Z0-9_-]*|(?:db|admin|root|app|master)[_-]?(?:secret|token)|(?:\b(?:secret|token)\b))\s*[:=]\s*(?P<val>['"]?[^\s'";,]{3,}['"]?)`)

// IsSensitiveFilename identifies filenames that typically contain sensitive credentials.
func IsSensitiveFilename(fileName, ext string) (bool, string) {
	fn := strings.ToLower(fileName)
	extLower := strings.ToLower(ext)
	if fn == "requirements.txt" || fn == "test-requirements.txt" {
		return false, ""
	}
	switch fn {
	case "password.txt", "passwords.txt":
		return true, "Password credential text file"
	case "credentials.txt", "credential.txt":
		return true, "Credential storage text file"
	case "secret.txt", "secrets.txt":
		return true, "Secret storage text file"
	case ".env":
		return true, "Environment configuration file"
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true, "Private SSH key file"
	case ".htpasswd":
		return true, "HTTP basic auth password file"
	default:
		codeExts := map[string]bool{".go": true, ".rs": true, ".js": true, ".ts": true, ".py": true, ".java": true, ".c": true, ".cpp": true, ".cs": true, ".rb": true, ".php": true}
		if strings.HasPrefix(fn, ".env") || extLower == ".env" || extLower == "env" {
			return true, "Environment configuration file"
		}
		if strings.HasPrefix(fn, "credentials.") && !codeExts[extLower] {
			return true, "Credential storage file"
		}
		if strings.HasPrefix(fn, "secrets.") && !codeExts[extLower] {
			return true, "Secret storage file"
		}
		if extLower == ".pem" || extLower == ".key" {
			return true, "Cryptographic key file"
		}
		if extLower == ".conf" || extLower == "conf" {
			return true, "Configuration credential file"
		}
		if (extLower == ".txt" || extLower == "txt") && strings.HasPrefix(fn, "leak") {
			return true, "Potential credential leak file"
		}
		if (extLower == ".txt" || extLower == "txt") && strings.HasPrefix(fn, "test") {
			return true, "Test credential text file"
		}
		if (extLower == ".txt" || extLower == "txt") && (strings.HasSuffix(fn, "_secret.txt") || strings.Contains(fn, "secret")) {
			return true, "Secret storage text file"
		}
		return false, ""
	}
}

// ComputeSecretConfidence evaluates context and returns confidence level and severity.
func ComputeSecretConfidence(filePath, line, key, val string, isSensitiveFile bool) (int, string, string, bool) {
	lineLower := strings.ToLower(line)
	valClean := strings.Trim(val, `'"`)
	valLower := strings.ToLower(valClean)
	ext := strings.ToLower(filepath.Ext(filePath))

	sourceExts := map[string]bool{".go": true, ".rs": true, ".js": true, ".ts": true, ".py": true, ".java": true, ".c": true, ".cpp": true, ".cs": true, ".rb": true, ".php": true}
	isSource := sourceExts[ext]

	// In source code files, hardcoded credentials are string literals ("..." or '...')
	isQuoted := (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
		(strings.HasPrefix(val, `'`) && strings.HasSuffix(val, `'`))
	if isSource && (!isQuoted || strings.Contains(line, "!=")) {
		return 0, "", "", false
	}
	if isSource && strings.Contains(line, "==") {
		// Only flag equality comparison if compared value is a long/sensitive string token (len >= 8, not pure digits)
		if len(valClean) < 8 || hasOnlyDigits(valClean) {
			return 0, "", "", false
		}
	}

	codeTokens := map[string]bool{
		"true": true, "false": true, "bool": true, "string": true, "int": true,
		"usize": true, "none": true, "null": true, "nil": true, "undefined": true,
		"void": true, "any": true, "err": true, "error": true, "regex": true, "scan_secrets": true,
	}
	if codeTokens[valLower] || strings.HasPrefix(valClean, "!") || strings.HasPrefix(valClean, "&") ||
		strings.Contains(valClean, "::") || strings.Contains(valClean, "=>") ||
		strings.ContainsAny(valClean, "(){}[]") {
		return 0, "", "", false
	}

	// Candidate Key Name Filtering:
	// Reject variable names that describe keys/names/types rather than credentials themselves.
	keyLower := strings.ToLower(key)
	nonCredentialKeys := map[string]bool{
		"key": true, "keylower": true, "key_lower": true, "lowerkey": true, "lower_key": true,
		"keyname": true, "key_name": true, "keyvalue": true, "key_value": true,
		"secretname": true, "secret_name": true, "tokenname": true, "token_name": true,
		"apikeyname": true, "api_key_name": true,
	}
	if nonCredentialKeys[keyLower] {
		return 0, "", "", false
	}

	// Reject environment variable reference calls: os.getenv, os.environ, process.env, $env:, etc.
	if strings.Contains(valLower, "os.getenv") || strings.Contains(valLower, "os.environ") ||
		strings.Contains(valLower, "process.env") || strings.Contains(valLower, "$env:") ||
		strings.Contains(lineLower, "os.getenv") || strings.Contains(lineLower, "os.environ") ||
		strings.Contains(lineLower, "process.env") || strings.Contains(lineLower, "$env:") {
		return 0, "", "", false
	}

	score := 0

	// 1. Filename signal (+30)
	if isSensitiveFile {
		score += 30
	}

	// 2. Key name signal (+25)
	if strings.Contains(keyLower, "password") || strings.Contains(keyLower, "passwd") || strings.Contains(keyLower, "pwd") ||
		strings.Contains(keyLower, "api_key") || strings.Contains(keyLower, "apikey") ||
		strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "token") {
		score += 25
	} else {
		score += 15
	}

	// 3. Assignment operator (+20)
	if strings.Contains(line, "=") || strings.Contains(line, ":") {
		score += 20
	}

	// 4. Placeholder checks (-25)
	isPlaceholder := valLower == "your_password_here" ||
		valLower == "your_password" ||
		valLower == "your_api_key" ||
		strings.Contains(valLower, "<password>") ||
		strings.Contains(valLower, "<api_key>") ||
		valLower == "changeme" ||
		valLower == "placeholder" ||
		valLower == "example" ||
		valLower == "sample" ||
		valLower == "test" ||
		valLower == "todo" ||
		valLower == "xxx" ||
		valLower == "xxxx" ||
		strings.HasPrefix(valLower, "$") ||
		strings.HasPrefix(valLower, "%") ||
		strings.Contains(valLower, "${") ||
		strings.Contains(lineLower, "read-host") ||
		strings.Contains(lineLower, "param(") ||
		strings.Contains(lineLower, "os.getenv") ||
		strings.Contains(lineLower, "os.environ") ||
		strings.Contains(lineLower, "process.env") ||
		strings.Contains(lineLower, "$env:") ||
		valClean == "..." ||
		strings.HasPrefix(valClean, "...") ||
		valLower == "password"

	if isPlaceholder {
		score -= 25
	} else {
		if len(valClean) >= 3 {
			score += 15
		}
		if strings.ContainsAny(valClean, "@-_") || (hasDigit(valClean) && hasAlpha(valClean)) {
			score += 10
		}
	}

	// Comments and documentation context (-20)
	trimmed := strings.TrimSpace(line)
	isComment := strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, ";")
	if isComment {
		score -= 20
	}

	if strings.Contains(lineLower, "example") || strings.Contains(lineLower, "fake") ||
		strings.Contains(lineLower, "intentionally") || strings.Contains(lineLower, "syntax:") ||
		strings.Contains(lineLower, "format:") {
		score -= 20
	}

	// Dynamic Credential Weighting:
	// When an exact assignment is detected in any text/config file,
	// award high confidence regardless of whether filename is strictly password.txt.
	isExactCredential := !isPlaceholder && !isComment && len(valClean) >= 4 &&
		(isQuoted || isSensitiveFile || ext == ".txt" || ext == ".conf" || ext == ".env" || ext == ".ini") &&
		(keyLower == "password" || keyLower == "passwd" || keyLower == "pwd" ||
			keyLower == "api_key" || keyLower == "apikey" || keyLower == "secret" || keyLower == "token")

	if isExactCredential {
		score += 30
	}

	// 5. File type / context (+10 source/config, -30 doc)
	docExts := map[string]bool{".md": true, ".markdown": true, ".rst": true, ".adoc": true}
	if docExts[ext] || (ext == ".txt" && !isSensitiveFile && !isExactCredential) {
		score -= 30
	} else {
		score += 10
	}

	// 7. Test fixture directory / test file (-40)
	pathLower := strings.ToLower(filePath)
	isTargetCredentialFile := strings.HasSuffix(filePath, "password.txt") ||
		isSensitiveFile ||
		(isExactCredential && !strings.Contains(pathLower, "fixtures") && !strings.Contains(pathLower, "mock"))

	if !isTargetCredentialFile && (strings.Contains(pathLower, "test") || strings.Contains(pathLower, "fixture") || strings.Contains(pathLower, "mock")) {
		score -= 40
	}

	// Determine confidence and severity based on calibrated score
	if score >= 80 {
		return score, "HIGH", "HIGH", true
	} else if score >= 50 {
		return score, "MEDIUM", "MEDIUM", true
	} else if score >= 20 {
		return score, "LOW", "LOW", true
	} else {
		return score, "IGNORE", "", false
	}
}

func hasDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func hasAlpha(s string) bool {
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

func hasOnlyDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var compRegex = regexp.MustCompile(`(?i)(?:^|[\s,;{(])(?P<key>[a-zA-Z0-9_-]*(?:password|passwd|pwd|api[_-]?key|apikey|jwt[_-]?secret|auth[_-]?token|access[_-]?token|client[_-]?secret)[a-zA-Z0-9_-]*)\s*==\s*(?P<val>['"][^\s'";,]{8,}['"])`)

// ScanCredentialAssignments analyzes a single line for credential assignments and comparisons using context + confidence.
func ScanCredentialAssignments(filePath, line string, lineNum int, isSensitiveFile bool, counter *int) []Finding {
	var findings []Finding
	if matches := assignRegex.FindStringSubmatch(line); len(matches) > 2 {
		key := matches[1]
		val := matches[2]
		if _, confStr, sevStr, ok := ComputeSecretConfidence(filePath, line, key, val, isSensitiveFile); ok {
			*counter++
			maskedEvidence := fmt.Sprintf("%s=********", key)
			title := "Hardcoded Secret Detected"
			ruleID := "VG-SECRET-003"
			keyLower := strings.ToLower(key)
			if strings.Contains(keyLower, "password") || strings.Contains(keyLower, "passwd") || strings.Contains(keyLower, "pwd") {
				title = "Hardcoded Password Detected"
				ruleID = "VG-SECRET-001"
			} else if strings.Contains(keyLower, "api") {
				title = "Hardcoded API Key Detected"
				ruleID = "VG-SECRET-002"
			}

			findings = append(findings, Finding{
				ID:             ruleID,
				Category:       "secret",
				Severity:       sevStr,
				Title:          title,
				Description:    fmt.Sprintf("Hardcoded credential assignment detected for key '%s'.", key),
				File:           filePath,
				Line:           lineNum,
				Evidence:       maskedEvidence,
				Recommendation: "Store credentials in environment variables or a secure secrets vault.",
				Confidence:     confStr,
			})
		}
	} else if compMatches := compRegex.FindStringSubmatch(line); len(compMatches) > 2 {
		key := compMatches[1]
		val := compMatches[2]
		if _, confStr, sevStr, ok := ComputeSecretConfidence(filePath, line, key, val, isSensitiveFile); ok {
			*counter++
			maskedEvidence := fmt.Sprintf("%s==********", key)
			title := "Hardcoded Secret in Comparison"
			ruleID := "VG-SECRET-003"
			keyLower := strings.ToLower(key)
			if strings.Contains(keyLower, "password") || strings.Contains(keyLower, "passwd") || strings.Contains(keyLower, "pwd") {
				title = "Hardcoded Password in Comparison"
				ruleID = "VG-SECRET-001"
			} else if strings.Contains(keyLower, "api") {
				title = "Hardcoded API Key in Comparison"
				ruleID = "VG-SECRET-002"
			}

			findings = append(findings, Finding{
				ID:             ruleID,
				Category:       "secret",
				Severity:       sevStr,
				Title:          title,
				Description:    fmt.Sprintf("Hardcoded credential comparison check detected for key '%s'.", key),
				File:           filePath,
				Line:           lineNum,
				Evidence:       maskedEvidence,
				Recommendation: "Store credentials in environment variables or a secure secrets vault.",
				Confidence:     confStr,
			})
		}
	}
	return findings
}
