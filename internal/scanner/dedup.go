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
	if strings.Contains(title, "deserializ") || strings.Contains(rule, "DESER") {
		return "DESERIALIZATION"
	}

	if f.CanonicalRule != "" {
		return f.CanonicalRule
	}
	return f.RuleID
}

func detectorSpecificityRank(f Finding) int {
	r := strings.ToUpper(f.RuleID)
	if r == "" {
		r = strings.ToUpper(f.ID)
	}
	t := strings.ToLower(f.Title)
	ev := strings.ToLower(f.Evidence)

	if strings.Contains(r, "SEC-001") || strings.Contains(t, "aws") || strings.Contains(ev, "aws_access_key") || strings.Contains(ev, "akia") {
		return 10
	}
	if strings.Contains(r, "SEC-003") || strings.Contains(t, "github") || strings.Contains(ev, "ghp_") {
		return 9
	}
	if strings.Contains(r, "AUTH-003") || strings.Contains(t, "jwt") || strings.Contains(ev, "jwt_secret") {
		return 8
	}
	if strings.Contains(t, "database password") || strings.Contains(t, "db_password") || strings.Contains(ev, "db_password") || strings.Contains(ev, "database_url") {
		return 7
	}
	if strings.Contains(r, "SEC-002") || strings.Contains(t, "api key") || strings.Contains(t, "apikey") || strings.Contains(ev, "api_key") {
		return 6
	}
	if strings.Contains(r, "SEC-004") || strings.Contains(t, "slack") {
		return 5
	}
	if strings.Contains(r, "SEC-005") || strings.Contains(t, "private key") {
		return 4
	}
	if strings.Contains(r, "SECRET-001") || strings.Contains(r, "SECRET-002") || strings.Contains(r, "SECRET-003") || strings.Contains(r, "SEC-006") || strings.Contains(r, "SEC-007") || strings.Contains(r, "SEC-008") {
		return 3
	}
	if strings.Contains(r, "CFG-008") {
		return 2
	}
	return 1
}

func mergeGoFindings(group []Finding) Finding {
	// Pick the finding with highest severity and highest detector specificity as primary
	bestIdx := 0
	for i := 1; i < len(group); i++ {
		wI := severityWeight(group[i].Severity)
		wBest := severityWeight(group[bestIdx].Severity)
		if wI > wBest {
			bestIdx = i
		} else if wI == wBest {
			if detectorSpecificityRank(group[i]) > detectorSpecificityRank(group[bestIdx]) {
				bestIdx = i
			}
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

	// Standardize canonical title, rule, category and CWE
	hasDetector := func(needle string) bool {
		for _, d := range base.DetectorIDs {
			if strings.Contains(d, needle) {
				return true
			}
		}
		return false
	}
	evCombined := strings.ToLower(strings.Join(base.Evidences, " "))
	titleLower := strings.ToLower(base.Title)

	if hasDetector("SEC-001") || strings.Contains(titleLower, "aws") || strings.Contains(evCombined, "aws_access_key") || strings.Contains(evCombined, "akia") {
		base.Title = "Exposed AWS Credential"
		base.CanonicalRule = "VG-CANON-CRED-AWS"
		base.Category = "secret"
		base.Severity = "CRITICAL"
		base.CWE = "CWE-798"
	} else if hasDetector("SEC-003") || strings.Contains(titleLower, "github") || strings.Contains(evCombined, "ghp_") {
		base.Title = "Exposed GitHub Token"
		base.CanonicalRule = "VG-CANON-CRED-GITHUB"
		base.Category = "secret"
		base.Severity = "CRITICAL"
		base.CWE = "CWE-798"
	} else if hasDetector("AUTH-003") || strings.Contains(titleLower, "jwt") || strings.Contains(evCombined, "jwt") {
		base.Title = "Exposed JWT Secret"
		base.CanonicalRule = "VG-CANON-CRED-JWT"
		base.Category = "secret"
		base.Severity = "CRITICAL"
		base.CWE = "CWE-798"
	} else if strings.Contains(titleLower, "database password") || strings.Contains(evCombined, "db_password") || strings.Contains(evCombined, "database_url") || strings.Contains(evCombined, "db_pass") {
		base.Title = "Exposed Database Password"
		base.CanonicalRule = "VG-CANON-CRED-DB"
		base.Category = "secret"
		base.Severity = "CRITICAL"
		base.CWE = "CWE-798"
	} else if hasDetector("SEC-002") || hasDetector("SECRET-002") || strings.Contains(titleLower, "api key") || strings.Contains(evCombined, "api_key") || strings.Contains(evCombined, "apikey") {
		base.Title = "Exposed API Key"
		base.CanonicalRule = "VG-CANON-CRED-APIKEY"
		base.Category = "secret"
		base.Severity = "CRITICAL"
		base.CWE = "CWE-798"
	}

	// Pick clean key-value evidence if base evidence is bare value
	if !strings.Contains(base.Evidence, "=") {
		for _, e := range base.Evidences {
			if strings.Contains(e, "=") {
				base.Evidence = e
				break
			}
		}
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
