package scanner

import (
	"testing"
)

func TestSensitiveFilenameDetection(t *testing.T) {
	sensitiveCases := []struct {
		filename string
		ext      string
		expected bool
	}{
		{"password.txt", ".txt", true},
		{"passwords.txt", ".txt", true},
		{"credential.txt", ".txt", true},
		{"credentials.txt", ".txt", true},
		{"secret.txt", ".txt", true},
		{"secrets.txt", ".txt", true},
		{".env", "", true},
		{".env.production", "", true},
		{"id_rsa", "", true},
		{"id_ed25519", "", true},
		{".htpasswd", "", true},
		{"server.key", ".key", true},
		{"cert.pem", ".pem", true},
		{"app.conf", ".conf", true},
		{"leak_test.txt", ".txt", true},
		{"test_keys.txt", ".txt", true},
		{"api_secret.txt", ".txt", true},
		{"requirements.txt", ".txt", false},
		{"safe.go", ".go", false},
		{"README.md", ".md", false},
		{"clean.txt", ".txt", false},
	}

	for _, tc := range sensitiveCases {
		isSens, _ := IsSensitiveFilename(tc.filename, tc.ext)
		if isSens != tc.expected {
			t.Errorf("expected IsSensitiveFilename(%q, %q) = %v, got %v", tc.filename, tc.ext, tc.expected, isSens)
		}
	}
}

func TestLeakTestFile(t *testing.T) {
	counter := 0
	findings := ScanCredentialAssignments("leak_test.txt", "password"+" = \"super_secret_leak_123\"", 1, true, &counter)
	if len(findings) == 0 {
		t.Fatalf("expected finding for leak_test.txt assignment, got 0")
	}
	f := findings[0]
	if f.ID != "VG-SECRET-001" {
		t.Errorf("expected ID VG-SECRET-001, got %s", f.ID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Confidence != "HIGH" {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}
}

func TestPasswordTxtAssignment(t *testing.T) {
	counter := 0
	findings := ScanCredentialAssignments("password.txt", "password=123@admin", 1, true, &counter)
	if len(findings) == 0 {
		t.Fatalf("expected finding for password.txt assignment, got 0")
	}

	f := findings[0]
	if f.ID != "VG-SECRET-001" {
		t.Errorf("expected ID VG-SECRET-001, got %s", f.ID)
	}
	if f.Title != "Hardcoded Password Detected" {
		t.Errorf("expected title 'Hardcoded Password Detected', got %s", f.Title)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Confidence != "HIGH" {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}
	if f.Evidence != "password=********" {
		t.Errorf("expected masked evidence 'password=********', got %s", f.Evidence)
	}
}

func TestPositiveCredentialAssignments(t *testing.T) {
	cases := []struct {
		line          string
		expectedTitle string
	}{
		{"db_password=demo123", "Hardcoded Password Detected"},
		{"admin_password=demo123", "Hardcoded Password Detected"},
		{"api_key=demo-value", "Hardcoded API Key Detected"},
		{"API_KEY=demo-value", "Hardcoded API Key Detected"},
		{"secret=abc123", "Hardcoded Secret Detected"},
		{"token=abc123", "Hardcoded Secret Detected"},
	}

	for _, tc := range cases {
		counter := 0
		findings := ScanCredentialAssignments("config.env", tc.line, 1, false, &counter)
		if len(findings) == 0 {
			t.Fatalf("expected finding for %q, got 0", tc.line)
		}
		if findings[0].Title != tc.expectedTitle {
			t.Errorf("expected title %q for %q, got %q", tc.expectedTitle, tc.line, findings[0].Title)
		}
		if findings[0].Severity != "HIGH" && findings[0].Severity != "MEDIUM" {
			t.Errorf("expected HIGH or MEDIUM severity for %q, got %s", tc.line, findings[0].Severity)
		}
	}
}

func TestNegativeCases_NotBlocking(t *testing.T) {
	counter := 0

	// 1. Documentation example
	docFindings := ScanCredentialAssignments("README.md", `The format password=123@admin example is fake`, 10, false, &counter)
	for _, f := range docFindings {
		if f.Confidence == "HIGH" || f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			t.Errorf("documentation example should not have HIGH severity/confidence: %+v", f)
		}
	}

	// 2. Obvious placeholder
	placeholderFindings := ScanCredentialAssignments("config.example", "password=YOUR_PASSWORD_HERE", 5, false, &counter)
	for _, f := range placeholderFindings {
		if f.Confidence == "HIGH" || f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			t.Errorf("placeholder should not have HIGH severity/confidence: %+v", f)
		}
	}

	// 3. Comment line
	commentFindings := ScanCredentialAssignments("main.py", "# password=example", 1, false, &counter)
	if len(commentFindings) != 0 {
		t.Errorf("expected comment line to be ignored, got %+v", commentFindings)
	}

	// 4. Clean text
	cleanFindings := ScanCredentialAssignments("clean.txt", "This document contains no credentials.", 1, false, &counter)
	if len(cleanFindings) != 0 {
		t.Errorf("expected clean document to have 0 findings, got %+v", cleanFindings)
	}
}
