package report

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { border-bottom: 1px solid #ccc; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .score { font-size: 24px; font-weight: bold; }
        .cards { display: flex; gap: 20px; margin: 20px 0; }
        .card { flex: 1; padding: 20px; border-radius: 5px; text-align: center; font-weight: bold; }
        .card.critical { background: #ffebee; color: #c62828; }
        .card.high { background: #fff3e0; color: #ef6c00; }
        .card.medium { background: #fffde7; color: #fbc02d; }
        .card.low { background: #e0f7fa; color: #00838f; }
        .card.info { background: #eceff1; color: #455a64; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f8f8; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: #fff; }
        .badge.critical { background: #c62828; }
        .badge.high { background: #ef6c00; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #00838f; }
        .badge.info { background: #455a64; }
        .status-banner { padding: 15px; border-radius: 5px; font-weight: bold; font-size: 18px; text-align: center; }
        .status-passed { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .status-blocked { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>VibeGuard Security Report</h1>
                <p><strong>Project:</strong> {{.ProjectName}} | <strong>Scanned:</strong> {{.ScanTime}} | <strong>Files:</strong> {{.FilesScanned}}{{if .SuppressedCount}} | <strong>Suppressed:</strong> {{.SuppressedCount}}{{end}}{{if .OSVMode}} | <strong>OSV:</strong> {{.OSVMode}}{{end}}</p>
            </div>
            <div class="score">Score: {{.ScoreResult.Score}}/100</div>
        </div>

        <div class="status-banner {{if eq .GateResult.Status "PASSED"}}status-passed{{else}}status-blocked{{end}}">
            Deployment Status: {{.GateResult.Status}} - {{.GateResult.Reason}}
        </div>

        <h2>Severity Summary</h2>
        <div class="cards">
            <div class="card critical">Critical<br>{{.ScoreResult.CriticalCount}}</div>
            <div class="card high">High<br>{{.ScoreResult.HighCount}}</div>
            <div class="card medium">Medium<br>{{.ScoreResult.MediumCount}}</div>
            <div class="card low">Low<br>{{.ScoreResult.LowCount}}</div>
            <div class="card info">Info<br>{{.ScoreResult.InfoCount}}</div>
        </div>

        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Title</th>
                <th>File</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
            {{range .Findings}}
            <tr>
                <td><span class="badge {{.Severity | js}}">{{.Severity}}</span></td>
                <td>{{.ID}}</td>
                <td>{{.Title}}</td>
                <td>{{.File}}:{{.Line}}</td>
                <td>{{.Description}}</td>
                <td>{{.Recommendation}}</td>
            </tr>
            {{end}}
        </table>

        <h2>Dependency Vulnerabilities</h2>
        <table>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>Vulnerability ID</th>
                <th>Summary</th>
            </tr>
            {{range .Dependencies}}
                {{$pkg := .PackageName}}
                {{$ver := .InstalledVersion}}
                {{$eco := .Ecosystem}}
                {{range .Vulnerabilities}}
                <tr>
                    <td>{{$pkg}}</td>
                    <td>{{$ver}}</td>
                    <td>{{$eco}}</td>
                    <td>{{.ID}}</td>
                    <td>{{.Summary}}</td>
                </tr>
                {{end}}
            {{end}}
        </table>
    </div>
</body>
</html>`

func WriteHTMLReport(r *Report, outputPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		absPath = filepath.Clean(outputPath)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"js": func(s string) string {
			switch strings.ToUpper(s) {
			case "CRITICAL":
				return "critical"
			case "HIGH":
				return "high"
			case "MEDIUM":
				return "medium"
			case "LOW":
				return "low"
			case "INFO":
				return "info"
			default:
				return "info"
			}
		},
	}).Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	var f *os.File
	f, err = os.Create(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}
