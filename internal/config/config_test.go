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
}
