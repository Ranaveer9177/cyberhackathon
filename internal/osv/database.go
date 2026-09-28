package osv

import (
	"github.com/vibeguard/vibeguard/internal/database"
)

// ConvertDBRecordToOSV converts a database.VulnerabilityRecord to an osv.Vulnerability.
func ConvertDBRecordToOSV(r database.VulnerabilityRecord) Vulnerability {
	var ranges []Range
	for _, rng := range r.Ranges {
		var events []Event
		for _, ev := range rng.Events {
			events = append(events, Event{
				Introduced:   ev.Introduced,
				Fixed:        ev.Fixed,
				LastAffected: ev.LastAffected,
			})
		}
		ranges = append(ranges, Range{
			Type:   rng.Type,
			Events: events,
		})
	}

	var severityEntries []SeverityEntry
	if r.CVSS != "" {
		severityEntries = append(severityEntries, SeverityEntry{
			Type:  "CVSS_V3",
			Score: r.CVSS,
		})
	}

	dbSpecific := map[string]interface{}{
		"severity": r.Severity,
	}
	if len(r.CWE) > 0 {
		dbSpecific["cwe"] = r.CWE
	}

	return Vulnerability{
		ID:         r.ID,
		Summary:    r.Summary,
		Details:    r.Description,
		Aliases:    r.Aliases,
		Severity:   severityEntries,
		Affected: []AffectedEntry{
			{
				Package: AffectedPackage{
					Name:      r.Package,
					Ecosystem: r.Ecosystem,
				},
				Ranges:   ranges,
				Versions: r.AffectedVersions,
			},
		},
		DatabaseSpecific: dbSpecific,
	}
}

// QueryLocalDatabase checks the local offline security database for the given package and version.
func QueryLocalDatabase(name, version, ecosystem string) ([]Vulnerability, bool) {
	db := database.GetDefaultDB()
	if db == nil {
		return nil, false
	}

	records := db.Lookup(name, version, ecosystem)
	if len(records) == 0 {
		return nil, false
	}

	var vulns []Vulnerability
	for _, rec := range records {
		vulns = append(vulns, ConvertDBRecordToOSV(rec))
	}
	return vulns, true
}
