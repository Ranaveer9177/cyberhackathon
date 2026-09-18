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

func PrintTerminalReport(r *Report) {
	fmt.Println("========= VIBEGUARD SECURITY REPORT =========")
	fmt.Printf("Project: %s\n", r.ProjectName)
	if r.CommitHash != "" {
		fmt.Printf("Commit:  %s\n", r.CommitHash)
	}
	if r.Branch != "" {
		fmt.Printf("Branch:  %s\n", r.Branch)
	}
	if r.Remote != "" {
		fmt.Printf("Remote:  %s\n", r.Remote)
	}
	fmt.Printf("Scan Time: %s\n", r.ScanTime)
	fmt.Printf("Files Scanned: %d\n", r.FilesScanned)
	fmt.Println("---------------------------------------------")
	fmt.Printf("Severity Counts:\n")
	fmt.Printf("Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
		r.ScoreResult.CriticalCount,
		r.ScoreResult.HighCount,
		r.ScoreResult.MediumCount,
		r.ScoreResult.LowCount,
		r.ScoreResult.InfoCount)

	fmt.Println("---------------------------------------------")
	fmt.Printf("Category Breakdown:\n")
	fmt.Printf("Secrets: %d, Source Code: %d, Dependencies: %d, Configuration: %d, Docker: %d, Git: %d\n",
		r.CategoryCounts.Secrets, r.CategoryCounts.SourceCode, r.CategoryCounts.Dependencies,
		r.CategoryCounts.Configuration, r.CategoryCounts.Docker, r.CategoryCounts.Git)

	fmt.Println("---------------------------------------------")
	fmt.Printf("Security Score: %d/%d\n", r.ScoreResult.Score, r.ScoreResult.Total)
	
	fmt.Println("---------------------------------------------")
	fmt.Println("Findings:")
	for _, f := range r.Findings {
		color := ColorWhite
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL", "HIGH":
			color = ColorRed
		case "MEDIUM":
			color = ColorYellow
		case "LOW":
			color = ColorCyan
		case "INFO":
			color = ColorWhite
		}
		fmt.Printf("%s[%s]%s %s - %s:%d\n", color, strings.ToUpper(f.Severity), ColorReset, f.ID, f.File, f.Line)
		fmt.Printf("  Description: %s\n", f.Description)
		fmt.Printf("  Recommendation: %s\n", f.Recommendation)
	}

	fmt.Println("---------------------------------------------")
	fmt.Println("Dependency Vulnerabilities:")
	for _, d := range r.Dependencies {
		for _, v := range d.Vulnerabilities {
			fmt.Printf("%s[%s]%s %s in %s (v%s) [%s]\n", ColorRed, "VULN", ColorReset, v.ID, d.PackageName, d.InstalledVersion, d.SourceFile)
			fmt.Printf("  Summary: %s\n", v.Summary)
		}
	}

	fmt.Println("---------------------------------------------")
	statusColor := ColorGreen
	if r.GateResult.Status == "BLOCKED" {
		statusColor = ColorRed
	}
	fmt.Printf("Deployment Status: %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	fmt.Printf("Reason: %s\n", r.GateResult.Reason)
	fmt.Println("=============================================")
}
