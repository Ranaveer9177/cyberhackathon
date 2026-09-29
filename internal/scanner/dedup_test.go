package scanner

import (
	"testing"
)

func TestDeduplicateFindings(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-001",
			Category:    "secret",
			Title:       "AWS Key",
			File:        "src/config.go",
			Line:        10,
			Evidence:    "MOCK_TOKEN_EVIDENCE_ABC",
		},
		{
			ID:          "VG-002",
			Category:    "secret",
			Title:       "AWS Key",
			File:        "src/config.go",
			Line:        10,
			Evidence:    "MOCK_TOKEN_EVIDENCE_ABC", // duplicate
		},
		{
			ID:          "VG-003",
			Category:    "sourcecode",
			Title:       "SQL Injection",
			File:        "src/db.go",
			Line:        45,
			Evidence:    "SELECT * FROM users WHERE id = " + "1",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(deduped))
	}

	if deduped[0].ID != "VG-001" {
		t.Errorf("expected first finding VG-001, got %s", deduped[0].ID)
	}
	if deduped[1].ID != "VG-003" {
		t.Errorf("expected second finding VG-003, got %s", deduped[1].ID)
	}
}

func TestCorrelateAWSKeyMultiDetector(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-SEC-001",
			RuleID:      "VG-SEC-001",
			Category:    "secret",
			Severity:    "CRITICAL",
			Title:       "AWS Access Key",
			File:        ".env",
			Line:        14,
			Evidence:    "AKIA" + "IOSFODNN7EXAMPLE",
			Confidence:  "HIGH",
		},
		{
			ID:          "VG-CFG-008",
			RuleID:      "VG-CFG-008",
			Category:    "configuration",
			Severity:    "CRITICAL",
			Title:       "Hardcoded Secret in Configuration File",
			File:        ".env",
			Line:        14,
			Evidence:    "AWS_ACCESS_KEY_ID=AKIAIOSF****",
			Confidence:  "HIGH",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 canonical finding for AWS key, got %d", len(deduped))
	}
	f := deduped[0]
	if f.Title != "Exposed AWS Credential" {
		t.Errorf("expected title 'Exposed AWS Credential', got '%s'", f.Title)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
	if len(f.DetectorIDs) < 2 {
		t.Errorf("expected at least 2 detector IDs credited, got %v", f.DetectorIDs)
	}
	if f.Evidence != "AWS_ACCESS_KEY_ID=AKIAIOSF****" {
		t.Errorf("expected clean key=val evidence, got %s", f.Evidence)
	}
}

func TestCorrelateGitHubTokenMultiDetector(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-SEC-003",
			RuleID:      "VG-SEC-003",
			Category:    "secret",
			Severity:    "CRITICAL",
			Title:       "GitHub Token",
			File:        ".env",
			Line:        20,
			Evidence:    "ghp_1234567890abcdef1234567890abcdef12",
			Confidence:  "HIGH",
		},
		{
			ID:          "VG-CFG-008",
			RuleID:      "VG-CFG-008",
			Category:    "configuration",
			Severity:    "CRITICAL",
			Title:       "Hardcoded Secret in Configuration File",
			File:        ".env",
			Line:        20,
			Evidence:    "GITHUB_TOKEN=ghp_1234****",
			Confidence:  "HIGH",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 canonical finding for GitHub token, got %d", len(deduped))
	}
	f := deduped[0]
	if f.Title != "Exposed GitHub Token" {
		t.Errorf("expected title 'Exposed GitHub Token', got '%s'", f.Title)
	}
}

func TestCorrelateJWTSecretMultiDetector(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-AUTH-003",
			RuleID:      "VG-AUTH-003",
			Category:    "secret",
			Severity:    "HIGH",
			Title:       "Hardcoded Authentication Token",
			File:        ".env",
			Line:        25,
			Evidence:    "JWT_SECRET=super_secret_jwt_key_123456",
			Confidence:  "HIGH",
		},
		{
			ID:          "VG-CFG-008",
			RuleID:      "VG-CFG-008",
			Category:    "configuration",
			Severity:    "CRITICAL",
			Title:       "Hardcoded Secret in Configuration File",
			File:        ".env",
			Line:        25,
			Evidence:    "JWT_SECRET=super_se****",
			Confidence:  "HIGH",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 canonical finding for JWT secret, got %d", len(deduped))
	}
	f := deduped[0]
	if f.Title != "Exposed JWT Secret" {
		t.Errorf("expected title 'Exposed JWT Secret', got '%s'", f.Title)
	}
}

func TestCorrelateDatabasePasswordMultiDetector(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-SECRET-001",
			RuleID:      "VG-SECRET-001",
			Category:    "secret",
			Severity:    "HIGH",
			Title:       "Hardcoded Password Detected",
			File:        ".env",
			Line:        6,
			Evidence:    "db_password=SuperSecret123!",
			Confidence:  "HIGH",
		},
		{
			ID:          "VG-CFG-008",
			RuleID:      "VG-CFG-008",
			Category:    "configuration",
			Severity:    "CRITICAL",
			Title:       "Hardcoded Secret in Configuration File",
			File:        ".env",
			Line:        6,
			Evidence:    "DB_PASSWORD=SuperSec****",
			Confidence:  "HIGH",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 canonical finding for Database Password, got %d", len(deduped))
	}
	f := deduped[0]
	if f.Title != "Exposed Database Password" {
		t.Errorf("expected title 'Exposed Database Password', got '%s'", f.Title)
	}
}

func TestCorrelateAPIKeyMultiDetector(t *testing.T) {
	raw := []Finding{
		{
			ID:          "VG-SEC-002",
			RuleID:      "VG-SEC-002",
			Category:    "secret",
			Severity:    "CRITICAL",
			Title:       "Generic API Key",
			File:        ".env",
			Line:        9,
			Evidence:    "api_key=sk-demo-1234567890abcdef",
			Confidence:  "HIGH",
		},
		{
			ID:          "VG-CFG-008",
			RuleID:      "VG-CFG-008",
			Category:    "configuration",
			Severity:    "CRITICAL",
			Title:       "Hardcoded Secret in Configuration File",
			File:        ".env",
			Line:        9,
			Evidence:    "API_KEY=sk-demo-****",
			Confidence:  "HIGH",
		},
	}

	deduped := DeduplicateFindings(raw)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 canonical finding for API Key, got %d", len(deduped))
	}
	f := deduped[0]
	if f.Title != "Exposed API Key" {
		t.Errorf("expected title 'Exposed API Key', got '%s'", f.Title)
	}
}

