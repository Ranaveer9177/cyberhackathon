package report

import (
	"encoding/json"
	"os"
	"strings"
)

// Standard SARIF 2.1.0 data structures
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SarifDescription `json:"shortDescription"`
	DefaultConfig    SarifConfig      `json:"defaultConfiguration"`
}

type SarifDescription struct {
	Text string `json:"text"`
}

type SarifConfig struct {
	Level string `json:"level"`
}

type SarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SarifDescription `json:"message"`
	Locations []SarifLocation  `json:"locations"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

func severityToSarifLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// GenerateSarif creates a SARIF 2.1.0 struct from a VibeGuard Report.
func GenerateSarif(r *Report) *SarifLog {
	rulesMap := make(map[string]SarifRule)
	var results []SarifResult

	for _, f := range r.Findings {
		level := severityToSarifLevel(f.Severity)
		if _, exists := rulesMap[f.ID]; !exists {
			rulesMap[f.ID] = SarifRule{
				ID:   f.ID,
				Name: f.Title,
				ShortDescription: SarifDescription{
					Text: f.Description,
				},
				DefaultConfig: SarifConfig{
					Level: level,
				},
			}
		}

		line := f.Line
		if line < 1 {
			line = 1
		}

		msg := f.Title
		if f.Description != "" && f.Description != f.Title {
			msg = f.Title + ": " + f.Description
		}

		results = append(results, SarifResult{
			RuleID: f.ID,
			Level:  level,
			Message: SarifDescription{
				Text: msg,
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: f.File,
						},
						Region: SarifRegion{
							StartLine: line,
						},
					},
				},
			},
		})
	}

	var rules []SarifRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	return &SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "VibeGuard",
						Version:        "4.4.0",
						InformationURI: "https://github.com/Ranaveer9177/cyberhackathon",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// WriteSarifReport writes the SARIF report to a file.
func WriteSarifReport(r *Report, filePath string) error {
	sarif := GenerateSarif(r)
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}
