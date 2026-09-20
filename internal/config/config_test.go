package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.BlockOn) != 2 {
		t.Fatalf("expected 2 block_on items, got %d", len(cfg.BlockOn))
	}
	if !cfg.DependencyScan || !cfg.SecretScan || !cfg.SourceScan {
		t.Errorf("expected all scan modules enabled by default")
	}
	if !cfg.FailClosed {
		t.Errorf("expected fail_closed to be true by default")
	}
	if cfg.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", cfg.ScanMode)
	}
}

func TestCreateDefaultConfigAndLoad(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create default config file
	if err := CreateDefaultConfig(tempDir); err != nil {
		t.Fatalf("CreateDefaultConfig failed: %v", err)
	}

	// Verify file existence
	cfgFile := filepath.Join(tempDir, ".vibeguard", "config.json")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Fatalf("expected %s to exist", cfgFile)
	}

	// Load config
	loaded, err := LoadConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !loaded.FailClosed {
		t.Errorf("expected loaded fail_closed to be true")
	}
	if loaded.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", loaded.ScanMode)
	}
	if len(loaded.Exclude) == 0 {
		t.Errorf("expected default exclusions to be loaded")
	}
}

func TestIsExcluded(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		path     string
		expected bool
	}{
		{"tests/safe.go", true},
		{"md files/README.md", true},
		{"code.md", true},
		{"finalreport.md", true},
		{"reports/audit.json", true},
		{".git/config", true},
		{".vibeguard/config.json", true},
		{"output.md", true},
		{"output2.md", true},
		{"test output.md", true},
		{"test3.md", true},
		{"test4.md", true},
		{"test5.md", true},
		{"NEW_LAPTOP_SETUP.md", true},
		{"rules/README.md", true},
		{"src/main.go", false},
		{"src/main.rs", false},
		{"internal/scanner/runner.go", false},
		{"cmd/vibeguard/main.go", false},
		{".", false},
		{"", false},
	}

	for _, tt := range tests {
		result := cfg.IsExcluded(tt.path)
		if result != tt.expected {
			t.Errorf("IsExcluded(%q) = %v; want %v", tt.path, result, tt.expected)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}

	// Invalid scan_mode
	badMode := DefaultConfig()
	badMode.ScanMode = "invalid"
	if err := badMode.Validate(); err == nil {
		t.Errorf("expected error for invalid scan_mode")
	}

	// Invalid report_format
	badFmt := DefaultConfig()
	badFmt.ReportFormat = "xml"
	if err := badFmt.Validate(); err == nil {
		t.Errorf("expected error for invalid report_format")
	}

	// Invalid block_on
	badBlock := DefaultConfig()
	badBlock.BlockOn = []string{"critical", "super_bad"}
	if err := badBlock.Validate(); err == nil {
		t.Errorf("expected error for invalid block_on severity")
	}

	// Empty pattern in exclude
	badExclude := DefaultConfig()
	badExclude.Exclude = []string{""}
	if err := badExclude.Validate(); err == nil {
		t.Errorf("expected error for empty pattern in exclude list")
	}
}

