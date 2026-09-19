package osv

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	rceRegex             = regexp.MustCompile(`(?i)\b(rce|remote code execution|arbitrary code execution)\b`)
	criticalKeywordRegex = regexp.MustCompile(`(?i)\b(critical severity)\b`)
	highKeywordRegex     = regexp.MustCompile(`(?i)\b(command injection|sql injection|sqli|prototype pollution|authentication bypass|privilege escalation)\b`)
	mediumKeywordRegex   = regexp.MustCompile(`(?i)\b(cross-site scripting|xss|open redirect|directory traversal|path traversal|csrf|denial of service|dos|ssrf)\b`)
	lowKeywordRegex      = regexp.MustCompile(`(?i)\b(information disclosure|sensitive data exposure|debug information)\b`)
)

// DetermineSeverity evaluates an OSV vulnerability and maps it to CRITICAL, HIGH, MEDIUM, or LOW.
func DetermineSeverity(v Vulnerability) string {
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
