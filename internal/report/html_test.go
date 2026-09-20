package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestHTMLEscapingSecurity(t *testing.T) {
	maliciousTitle := `<script>alert("xss")</script>`
	maliciousDesc := `"><img src=x onerror=alert(1)>`
	maliciousRec := `<b onmouseover=alert(1)>click me</b>`
	maliciousFile := `dir/<svg onload=alert(1)>/test.go`

	r := &Report{
		ProjectName:  "SecurityTest",
		FilesScanned: 1,
		Findings: []scanner.Finding{
			{
				ID:             "VG-999",
				Category:       "secret",
				Severity:       "HIGH",
				Title:          maliciousTitle,
				Description:    maliciousDesc,
				Recommendation: maliciousRec,
				File:           maliciousFile,
				Line:           10,
			},
		},
	}

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.html")

	if err := WriteHTMLReport(r, reportPath); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}

	contentBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read written HTML report: %v", err)
	}
	content := string(contentBytes)

	// Verify dangerous raw script tags are NOT present
	if strings.Contains(content, `<script>alert("xss")</script>`) {
		t.Errorf("HTML report contains unescaped script tag!")
	}
	if strings.Contains(content, `<img src=x onerror=alert(1)>`) {
		t.Errorf("HTML report contains unescaped img tag!")
	}
	if strings.Contains(content, `<svg onload=alert(1)>`) {
		t.Errorf("HTML report contains unescaped svg tag!")
	}

	// Verify properly escaped entity representations ARE present
	if !strings.Contains(content, `&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;`) {
		t.Errorf("expected escaped script tag in HTML report, got:\n%s", content)
	}
}
