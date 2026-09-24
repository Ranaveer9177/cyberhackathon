package scanner

import (
	"strings"
)

// NormalizeFindingKey generates a deterministic deduplication key for a finding.
func NormalizeFindingKey(f *Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.ComputeFingerprint()
}

func filepathClean(p string) string {
	return strings.TrimPrefix(strings.TrimSpace(p), "./")
}

// DeduplicateFindings removes duplicate findings while preserving discovery order.
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	seen := make(map[string]bool, len(findings))
	deduped := make([]Finding, 0, len(findings))

	for _, f := range findings {
		if f.Column <= 0 {
			f.Column = 1
		}
		if f.RuleID == "" {
			f.RuleID = f.ID
		}
		if f.Fingerprint == "" {
			f.Fingerprint = f.ComputeFingerprint()
		}

		key := f.Fingerprint
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}

	return deduped
}
