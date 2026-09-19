package report

import (
	"fmt"
	"strings"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorGray   = "\033[90m"
	ColorBold   = "\033[1m"
)

type CategoryCounts struct {
	Secrets       int
	SourceCode    int
	Dependencies  int
	Configuration int
	Docker        int
	Git           int
}

type Report struct {
	ProjectName    string
	CommitHash     string
	Branch         string
	Remote         string
	ScanTime       string
	FilesScanned   int
	Findings       []scanner.Finding
	Dependencies   []osv.VulnResult
	ScoreResult    risk.ScoreResult
	GateResult     gate.GateResult
	CategoryCounts CategoryCounts
}

func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func severityColor(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return ColorRed
	case "MEDIUM":
		return ColorYellow
	case "LOW":
		return ColorCyan
	default:
		return ColorWhite
	}
}

func getBestFixedVersion(vulns []osv.Vulnerability) string {
	var bestFix string
	for _, v := range vulns {
		for _, aff := range v.Affected {
			for _, r := range aff.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed != "" {
						if bestFix == "" || ev.Fixed > bestFix {
							bestFix = ev.Fixed
						}
					}
				}
			}
		}
	}
	return bestFix
}

func PrintTerminalReport(r *Report) {
	fmt.Println("========= VIBEGUARD SECURITY REPORT =========")
	fmt.Printf("Project:       %s\n", r.ProjectName)
	if r.Branch != "" {
		fmt.Printf("Branch:        %s\n", r.Branch)
	}
	if r.CommitHash != "" {
		fmt.Printf("Commit:        %s\n", r.CommitHash)
	}
	if r.Remote != "" {
		fmt.Printf("Remote:        %s\n", r.Remote)
	}
	fmt.Printf("Scan Time:     %s\n", r.ScanTime)
	fmt.Printf("Files Scanned: %d\n", r.FilesScanned)

	fmt.Println("---------------------------------------------")
	riskLevel := "LOW RISK"
	scoreColor := ColorGreen
	if r.ScoreResult.Score < 60 {
		riskLevel = "CRITICAL RISK"
		scoreColor = ColorRed
	} else if r.ScoreResult.Score < 75 {
		riskLevel = "HIGH RISK"
		scoreColor = ColorRed
	} else if r.ScoreResult.Score < 90 {
		riskLevel = "MEDIUM RISK"
		scoreColor = ColorYellow
	}
	fmt.Printf("Security Score: %s%d/%d (%s)%s\n", scoreColor, r.ScoreResult.Score, r.ScoreResult.Total, riskLevel, ColorReset)

	statusColor := ColorGreen
	if r.GateResult.Status == "BLOCKED" {
		statusColor = ColorRed
	}
	fmt.Printf("Gate Status:    %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	if r.GateResult.Reason != "" {
		fmt.Printf("Reason:         %s\n", r.GateResult.Reason)
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Severity Counts:\n")
	fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		r.ScoreResult.CriticalCount,
		r.ScoreResult.HighCount,
		r.ScoreResult.MediumCount,
		r.ScoreResult.LowCount,
		r.ScoreResult.InfoCount)

	fmt.Printf("Category Breakdown:\n")
	fmt.Printf("  Secrets: %d | Source Code: %d | Dependencies: %d | Config: %d | Docker: %d | Git: %d\n",
		r.CategoryCounts.Secrets, r.CategoryCounts.SourceCode, r.CategoryCounts.Dependencies,
		r.CategoryCounts.Configuration, r.CategoryCounts.Docker, r.CategoryCounts.Git)

	// 1. Code & Secret / Configuration Findings (non-dependency)
	var codeFindings []scanner.Finding
	for _, f := range r.Findings {
		if strings.ToLower(f.Category) != "dependency" {
			codeFindings = append(codeFindings, f)
		}
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Code & Configuration Findings (%d):\n", len(codeFindings))
	if len(codeFindings) == 0 {
		fmt.Printf("  %s✓ No code, secret, or configuration issues detected.%s\n", ColorGreen, ColorReset)
	} else {
		for _, f := range codeFindings {
			c := severityColor(f.Severity)
			cat := strings.Title(strings.ToLower(f.Category))
			fmt.Printf("  %s[%s]%s %s (%s) - %s:%d\n", c, strings.ToUpper(f.Severity), ColorReset, f.ID, cat, f.File, f.Line)
			if f.Title != "" {
				fmt.Printf("    Title:          %s\n", f.Title)
			}
			if f.Description != "" && f.Description != f.Title {
				fmt.Printf("    Description:    %s\n", f.Description)
			}
			if f.Recommendation != "" {
				fmt.Printf("    Recommendation: %s\n", f.Recommendation)
			}
			fmt.Println()
		}
	}

	// 2. Dependency Vulnerabilities (Grouped by package for clean readability)
	totalVulns := 0
	for _, d := range r.Dependencies {
		totalVulns += len(d.Vulnerabilities)
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Dependency Vulnerabilities (%d vulnerable packages, %d total advisories):\n", len(r.Dependencies), totalVulns)
	if len(r.Dependencies) == 0 {
		fmt.Printf("  %s✓ No known vulnerabilities found in dependencies.%s\n", ColorGreen, ColorReset)
	} else {
		// Table Header
		fmt.Printf("  %-20s %-12s %-12s %-14s %s\n", "PACKAGE", "CURRENT", "SEVERITY", "ADVISORIES", "RECOMMENDED FIX")
		fmt.Println("  --------------------------------------------------------------------------------")

		for _, d := range r.Dependencies {
			maxSevRank := -1
			maxSevStr := "LOW"
			for _, v := range d.Vulnerabilities {
				sev := osv.DetermineSeverity(v)
				rank := severityRank(sev)
				if rank > maxSevRank {
					maxSevRank = rank
					maxSevStr = sev
				}
			}

			fixVer := getBestFixedVersion(d.Vulnerabilities)
			fixText := "Update package"
			if fixVer != "" {
				fixText = fmt.Sprintf("Upgrade to >= %s", fixVer)
			}

			sevColored := fmt.Sprintf("%s%-12s%s", severityColor(maxSevStr), maxSevStr, ColorReset)
			advCount := fmt.Sprintf("%d vulns", len(d.Vulnerabilities))

			pkgName := d.PackageName
			if len(pkgName) > 20 {
				pkgName = pkgName[:18] + ".."
			}

			instVer := d.InstalledVersion
			if len(instVer) > 12 {
				instVer = instVer[:10] + ".."
			}

			fmt.Printf("  %-20s %-12s %s %-14s %s\n", pkgName, instVer, sevColored, advCount, fixText)
		}

		// Advisory details (compact summary per package)
		fmt.Println()
		fmt.Println("  Key Advisory Highlights:")
		for _, d := range r.Dependencies {
			src := d.SourceFile
			if src != "" {
				src = fmt.Sprintf(" [%s]", src)
			}
			fmt.Printf("  • %s (%s)%s:\n", d.PackageName, d.InstalledVersion, src)

			maxShow := 2
			for idx, v := range d.Vulnerabilities {
				if idx >= maxShow {
					remaining := len(d.Vulnerabilities) - maxShow
					fmt.Printf("    %s... and %d more advisories%s\n", ColorGray, remaining, ColorReset)
					break
				}
				sev := osv.DetermineSeverity(v)
				c := severityColor(sev)
				summary := v.Summary
				if summary == "" {
					summary = v.Details
				}
				summary = strings.ReplaceAll(summary, "\n", " ")
				if len(summary) > 75 {
					summary = summary[:72] + "..."
				}
				fmt.Printf("    - %s%s%s [%s]: %s\n", c, v.ID, ColorReset, sev, summary)
			}
		}
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Deployment Status: %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	if r.GateResult.Reason != "" {
		fmt.Printf("Reason: %s\n", r.GateResult.Reason)
	}
	fmt.Println("=============================================")
}
