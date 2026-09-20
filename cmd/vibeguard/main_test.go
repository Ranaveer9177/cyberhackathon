package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/vibeguard/vibeguard/internal/osv"
)

func TestParseScanArgs_ValidFormats(t *testing.T) {
	formats := []string{"terminal", "json", "html", "sarif", "TERMINAL", "JSON", "Html", "SARIF"}

	for _, fmtStr := range formats {
		t.Run("Format_"+fmtStr, func(t *testing.T) {
			path, format, output, isHook, err := parseScanArgs([]string{".", "--format", fmtStr}, "terminal")
			if err != nil {
				t.Fatalf("expected format %q to be valid, got err: %v", fmtStr, err)
			}
			if format != strings.ToLower(fmtStr) {
				t.Errorf("expected normalized format %q, got %q", strings.ToLower(fmtStr), format)
			}
			if path != "." {
				t.Errorf("expected path '.', got %q", path)
			}
			if isHook {
				t.Errorf("expected isHook to be false")
			}
			if output != "" {
				t.Errorf("expected output to be empty, got %q", output)
			}
		})
	}
}

func TestParseScanArgs_InvalidFormat(t *testing.T) {
	invalidFormats := []string{"xml", "yaml", "csv", "text", "pdf"}

	for _, fmtStr := range invalidFormats {
		t.Run("Invalid_"+fmtStr, func(t *testing.T) {
			_, _, _, _, err := parseScanArgs([]string{".", "--format", fmtStr}, "terminal")
			if err == nil {
				t.Fatalf("expected format %q to return error, but got nil", fmtStr)
			}
			if !strings.Contains(err.Error(), "unsupported output format") {
				t.Errorf("expected 'unsupported output format' in error, got %q", err.Error())
			}
			if !strings.Contains(err.Error(), "terminal, json, html, sarif") {
				t.Errorf("expected supported formats list in error, got %q", err.Error())
			}
		})
	}
}

func TestParseScanArgs_MissingFormatArg(t *testing.T) {
	_, _, _, _, err := parseScanArgs([]string{".", "--format"}, "terminal")
	if err == nil {
		t.Fatal("expected error when --format is missing argument")
	}
	if !strings.Contains(err.Error(), "missing format argument") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseScanArgs_MissingOutputArg(t *testing.T) {
	_, _, _, _, err := parseScanArgs([]string{".", "--output"}, "terminal")
	if err == nil {
		t.Fatal("expected error when --output is missing argument")
	}
	if !strings.Contains(err.Error(), "missing output path argument") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseScanArgs_UnknownOption(t *testing.T) {
	_, _, _, _, err := parseScanArgs([]string{".", "--bogus-flag"}, "terminal")
	if err == nil {
		t.Fatal("expected error for unknown option")
	}
	if !strings.Contains(err.Error(), "unknown option") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseScanArgs_CustomOutputAndHookAndOffline(t *testing.T) {
	path, format, output, isHook, err := parseScanArgs([]string{"my-project", "-f", "sarif", "-o", "custom.sarif", "--hook", "--offline"}, "terminal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "my-project" {
		t.Errorf("expected path 'my-project', got %q", path)
	}
	if format != "sarif" {
		t.Errorf("expected format 'sarif', got %q", format)
	}
	if output != "custom.sarif" {
		t.Errorf("expected output 'custom.sarif', got %q", output)
	}
	if !isHook {
		t.Errorf("expected isHook to be true")
	}
	if !osv.IsOfflineMode() {
		t.Errorf("expected offline mode to be enabled")
	}
}

func TestDetermineOSVSeverity(t *testing.T) {
	v1 := osv.Vulnerability{
		DatabaseSpecific: map[string]interface{}{
			"severity": "HIGH",
		},
	}
	sev1 := determineOSVSeverity(v1)
	if sev1 != "HIGH" {
		t.Errorf("expected HIGH, got %s", sev1)
	}

	v2 := osv.Vulnerability{
		Severity: []osv.SeverityEntry{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // 9.8 Critical
		},
	}
	sev2 := determineOSVSeverity(v2)
	if sev2 != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", sev2)
	}
}

func TestHandleStatus_NonGit(t *testing.T) {
	tmpDir := t.TempDir()
	// Should execute without panic
	handleStatus(tmpDir)
}

func TestHandleStatus_Git(t *testing.T) {
	tmpDir := t.TempDir()
	_ = exec.Command("git", "init", tmpDir).Run()
	handleStatus(tmpDir)
}

func TestPrintUsage(t *testing.T) {
	// printUsage should not panic
	printUsage()
}

func TestVersionString(t *testing.T) {
	if version != "4.4.0" {
		t.Errorf("expected version 4.4.0, got %s", version)
	}
}

func TestPromptConsole(t *testing.T) {
	// Skip interactive hardware CONIN$/tty read during automated test runs
	t.Skip("skipping interactive console prompt in automated test suite")
}
