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

// DeduplicateFindings removes duplicate findings across 5 deduplication levels:
// Level 1: Exact duplicate by fingerprint
// Level 2: Same rule + same file + same line
// Level 3: Different rules targeting the same underlying security issue on the same line (e.g. secret + config rule)
// Level 4: Same sink + multiple taint/AST/SAST detectors
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	// Phase 1: Level 1 exact fingerprint deduplication
	seen := make(map[string]bool, len(findings))
	level1 := make([]Finding, 0, len(findings))

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
		if len(f.DetectorIDs) == 0 && f.RuleID != "" {
			f.DetectorIDs = []string{f.RuleID}
		}
		if len(f.Evidences) == 0 && f.Evidence != "" {
			f.Evidences = []string{f.Evidence}
		}

		key := f.Fingerprint
		if !seen[key] {
			seen[key] = true
			level1 = append(level1, f)
		}
	}

	// Phase 2: Level 3 & Level 4 - Same file and line semantic consolidation
	type lineKey struct {
		file   string
		line   int
		family string
	}

	groups := make(map[lineKey][]Finding)
	var standalone []Finding

	for _, f := range level1 {
		if f.Line > 0 {
			normFile := strings.ToLower(strings.ReplaceAll(f.File, "\\", "/"))
			family := classifyFindingFamily(&f)
			key := lineKey{file: normFile, line: f.Line, family: family}
			groups[key] = append(groups[key], f)
		} else {
			standalone = append(standalone, f)
		}
	}

	deduped := make([]Finding, 0, len(level1))
	for _, group := range groups {
		if len(group) == 1 {
			deduped = append(deduped, group[0])
		} else {
			deduped = append(deduped, mergeGoFindings(group))
		}
	}
	deduped = append(deduped, standalone...)

	return deduped
}

func classifyFindingFamily(f *Finding) string {
	cat := strings.ToLower(f.Category)
	title := strings.ToLower(f.Title)
	rule := strings.ToUpper(f.RuleID)

	if cat == "secret" || strings.Contains(title, "secret") || strings.Contains(title, "credential") || strings.Contains(title, "key") || strings.Contains(title, "token") || strings.Contains(rule, "SEC-") || strings.Contains(rule, "CFG-008") {
		return "CREDENTIAL"
	}
	if strings.Contains(title, "sql") || strings.Contains(rule, "SQL") {
		return "SQL_INJECTION"
	}
	if strings.Contains(title, "command") || strings.Contains(rule, "CMD") || strings.Contains(rule, "SAST-002") {
		return "COMMAND_INJECTION"
	}
	if strings.Contains(title, "ssrf") || strings.Contains(rule, "SSRF") {
		return "SSRF"
	}
	if strings.Contains(title, "path") || strings.Contains(rule, "PATH") {
		return "PATH_TRAVERSAL"
	}
	if strings.Contains(title, "xss") || strings.Contains(rule, "XSS") {
		return "XSS"
	}

	if f.CanonicalRule != "" {
		return f.CanonicalRule
	}
	return f.RuleID
}

func mergeGoFindings(group []Finding) Finding {
	// Pick the finding with highest severity as primary
	bestIdx := 0
	for i := 1; i < len(group); i++ {
		if severityWeight(group[i].Severity) > severityWeight(group[bestIdx].Severity) {
			bestIdx = i
		}
	}

	base := group[bestIdx]
	detectorMap := make(map[string]bool)
	evidenceMap := make(map[string]bool)
	relatedMap := make(map[string]bool)

	for _, d := range base.DetectorIDs {
		detectorMap[d] = true
	}
	if base.RuleID != "" {
		detectorMap[base.RuleID] = true
	}
	for _, e := range base.Evidences {
		evidenceMap[e] = true
	}
	if base.Evidence != "" {
		evidenceMap[base.Evidence] = true
	}

	for i, f := range group {
		if i == bestIdx {
			continue
		}
		relatedMap[f.ID] = true
		for _, d := range f.DetectorIDs {
			detectorMap[d] = true
		}
		if f.RuleID != "" {
			detectorMap[f.RuleID] = true
		}
		for _, e := range f.Evidences {
			evidenceMap[e] = true
		}
		if f.Evidence != "" {
			evidenceMap[f.Evidence] = true
		}
		if len(base.DataFlow) == 0 && len(f.DataFlow) > 0 {
			base.DataFlow = f.DataFlow
			base.Source = f.Source
			base.Sink = f.Sink
		}
	}

	base.DetectorIDs = make([]string, 0, len(detectorMap))
	for d := range detectorMap {
		base.DetectorIDs = append(base.DetectorIDs, d)
	}
	base.Evidences = make([]string, 0, len(evidenceMap))
	for e := range evidenceMap {
		base.Evidences = append(base.Evidences, e)
	}
	base.RelatedFindings = make([]string, 0, len(relatedMap))
	for r := range relatedMap {
		base.RelatedFindings = append(base.RelatedFindings, r)
	}

	return base
}

func severityWeight(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}
