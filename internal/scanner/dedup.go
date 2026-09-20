package scanner

import (
	"fmt"
	"strings"
)

// NormalizeFindingKey generates a deterministic deduplication key for a finding.
func NormalizeFindingKey(f *Finding) string {
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	title := strings.ToLower(strings.TrimSpace(f.Title))
	file := strings.ReplaceAll(filepathClean(f.File), "\\", "/")
	line := f.Line
	evidence := strings.TrimSpace(f.Evidence)
	if len(evidence) > 60 {
		evidence = evidence[:60]
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s", cat, title, file, line, evidence)
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
		key := NormalizeFindingKey(&f)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}

	return deduped
}
