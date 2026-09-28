package database

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareVersions compares two version strings (e.g. "4.17.20" vs "4.17.21", "v0.3.7" vs "v0.3.8").
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	clean1 := cleanVersion(v1)
	clean2 := cleanVersion(v2)

	if clean1 == clean2 {
		return 0
	}

	parts1 := splitVersion(clean1)
	parts2 := splitVersion(clean2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		n1, err1 := strconv.ParseInt(p1, 10, 64)
		n2, err2 := strconv.ParseInt(p2, 10, 64)

		if err1 == nil && err2 == nil {
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		} else {
			// Compare lexicographically if not purely numeric
			cmp := strings.Compare(p1, p2)
			if cmp != 0 {
				return cmp
			}
		}
	}

	return 0
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	v = strings.TrimPrefix(v, "==")
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimSpace(v)
	return v
}

func splitVersion(v string) []string {
	// Separate build metadata and prerelease tags
	v = strings.Split(v, "+")[0] // drop build metadata

	var parts []string
	subparts := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	for _, s := range subparts {
		s = strings.TrimSpace(s)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// MatchConstraint evaluates whether a version satisfies a single constraint string like "< 4.17.21" or ">= 1.0.0".
func MatchConstraint(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}

	// Handle multiple comma-separated constraints like ">= 1.0.0, < 2.0.0"
	if strings.Contains(constraint, ",") {
		subConstraints := strings.Split(constraint, ",")
		for _, sc := range subConstraints {
			if !MatchConstraint(version, sc) {
				return false
			}
		}
		return true
	}

	cleanVer := cleanVersion(version)

	if strings.HasPrefix(constraint, "<=") {
		target := cleanVersion(strings.TrimPrefix(constraint, "<="))
		return CompareVersions(cleanVer, target) <= 0
	} else if strings.HasPrefix(constraint, "<") {
		target := cleanVersion(strings.TrimPrefix(constraint, "<"))
		return CompareVersions(cleanVer, target) < 0
	} else if strings.HasPrefix(constraint, ">=") {
		target := cleanVersion(strings.TrimPrefix(constraint, ">="))
		return CompareVersions(cleanVer, target) >= 0
	} else if strings.HasPrefix(constraint, ">") {
		target := cleanVersion(strings.TrimPrefix(constraint, ">"))
		return CompareVersions(cleanVer, target) > 0
	} else if strings.HasPrefix(constraint, "==") {
		target := cleanVersion(strings.TrimPrefix(constraint, "=="))
		return CompareVersions(cleanVer, target) == 0
	} else if strings.HasPrefix(constraint, "=") {
		target := cleanVersion(strings.TrimPrefix(constraint, "="))
		return CompareVersions(cleanVer, target) == 0
	} else if strings.HasPrefix(constraint, "!=") {
		target := cleanVersion(strings.TrimPrefix(constraint, "!="))
		return CompareVersions(cleanVer, target) != 0
	}

	// Default to equality check
	return CompareVersions(cleanVer, cleanVersion(constraint)) == 0
}

// IsVulnerable determines whether the specified installed version is affected by this vulnerability.
func (r *VulnerabilityRecord) IsVulnerable(installedVersion string) bool {
	installed := cleanVersion(installedVersion)
	if installed == "" || installed == "unknown" {
		return false
	}

	// 1. Check structured RangeSpecs (highest accuracy from OSV format)
	if len(r.Ranges) > 0 {
		for _, rng := range r.Ranges {
			if rng.Type == "GIT" {
				continue // skip git hashes
			}

			// In OSV, each event sequence represents introduced -> fixed / last_affected
			var currentIntro string
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					currentIntro = ev.Introduced
				}

				if ev.Fixed != "" {
					introMet := true
					if currentIntro != "" && currentIntro != "0" {
						introMet = CompareVersions(installed, currentIntro) >= 0
					}
					fixedMet := CompareVersions(installed, ev.Fixed) < 0
					if introMet && fixedMet {
						return true
					}
					currentIntro = "" // reset for next range pair
				} else if ev.LastAffected != "" {
					introMet := true
					if currentIntro != "" && currentIntro != "0" {
						introMet = CompareVersions(installed, currentIntro) >= 0
					}
					lastMet := CompareVersions(installed, ev.LastAffected) <= 0
					if introMet && lastMet {
						return true
					}
					currentIntro = ""
				}
			}

			// If introduced was set with no fixed event yet, all versions >= introduced are vulnerable
			if currentIntro != "" {
				if currentIntro == "0" || CompareVersions(installed, currentIntro) >= 0 {
					return true
				}
			}
		}
	}

	// 2. Check AffectedVersions constraint strings (e.g. "< 4.17.21")
	if len(r.AffectedVersions) > 0 {
		for _, aff := range r.AffectedVersions {
			if MatchConstraint(installed, aff) {
				return true
			}
		}
	}

	// 3. Fallback: If FixedVersions specified, check if installed < lowest fixed version
	if len(r.FixedVersions) > 0 {
		for _, fix := range r.FixedVersions {
			if fix != "" && CompareVersions(installed, fix) < 0 {
				return true
			}
		}
	}

	return false
}

// FormatSemverFix returns a human-readable recommendation for remediation.
func (r *VulnerabilityRecord) FormatSemverFix() string {
	if len(r.FixedVersions) > 0 && r.FixedVersions[0] != "" {
		return fmt.Sprintf("Upgrade to >= %s", r.FixedVersions[0])
	}
	for _, rng := range r.Ranges {
		for _, ev := range rng.Events {
			if ev.Fixed != "" {
				return fmt.Sprintf("Upgrade to >= %s", ev.Fixed)
			}
		}
	}
	return "Update package"
}
