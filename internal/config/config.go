package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents VibeGuard's project-level configuration stored in .vibeguard/config.json
type Config struct {
	BlockOn        []string `json:"block_on"`        // ["critical", "high"]
	ScanMode       string   `json:"scan_mode"`       // "full" or "changed"
	DependencyScan bool     `json:"dependency_scan"`
	SecretScan     bool     `json:"secret_scan"`
	SourceScan     bool     `json:"source_scan"`
	ReportFormat   string   `json:"report_format"`   // "terminal", "json", "html"
	FailClosed     bool     `json:"fail_closed"`     // block on scanner failure
	Exclude        []string `json:"exclude"`         // files/directories to exclude
}

// DefaultConfig returns sensible default security configuration.
func DefaultConfig() *Config {
	return &Config{
		BlockOn:        []string{"critical", "high"},
		ScanMode:       "full",
		DependencyScan: true,
		SecretScan:     true,
		SourceScan:     true,
		ReportFormat:   "terminal",
		FailClosed:     true,
		Exclude: []string{
			".git",
			".vibeguard",
			"reports",
			"md files",
			"tests",
			"code.md",
			"finalreport.md",
			"output.md",
			"output2.md",
			"test output.md",
			"test3.md",
			"test4.md",
			"test5.md",
			"NEW_LAPTOP_SETUP.md",
			"rules",
		},
	}
}

// IsExcluded evaluates whether relPath matches any configured exclusion pattern.
func (c *Config) IsExcluded(relPath string) bool {
	if relPath == "" || relPath == "." {
		return false
	}

	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	cleanPath = strings.TrimPrefix(cleanPath, "./")
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	for _, pattern := range c.Exclude {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		cleanPattern := filepath.ToSlash(filepath.Clean(pattern))
		cleanPattern = strings.TrimPrefix(cleanPattern, "./")
		cleanPattern = strings.TrimPrefix(cleanPattern, "/")

		// 1. Exact match
		if cleanPath == cleanPattern {
			return true
		}

		// 2. Directory subtree match (e.g. "tests" matches "tests/sast/vulnerable.go")
		if strings.HasPrefix(cleanPath, cleanPattern+"/") {
			return true
		}

		// 3. Basename match for exact filenames (e.g. "code.md" matches "code.md")
		if filepath.Base(cleanPath) == cleanPattern {
			return true
		}
	}

	return false
}

// Validate ensures configuration values are compliant with supported options.
func (c *Config) Validate() error {
	mode := strings.ToLower(strings.TrimSpace(c.ScanMode))
	if mode != "full" && mode != "changed" {
		return fmt.Errorf("invalid scan_mode '%s': must be 'full' or 'changed'", c.ScanMode)
	}

	fmtLower := strings.ToLower(strings.TrimSpace(c.ReportFormat))
	if fmtLower != "terminal" && fmtLower != "json" && fmtLower != "html" {
		return fmt.Errorf("invalid report_format '%s': must be 'terminal', 'json', or 'html'", c.ReportFormat)
	}

	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	for _, b := range c.BlockOn {
		b = strings.ToLower(strings.TrimSpace(b))
		if !validSeverities[b] {
			return fmt.Errorf("invalid severity in block_on '%s'", b)
		}
	}

	for _, exc := range c.Exclude {
		if strings.TrimSpace(exc) == "" {
			return fmt.Errorf("exclude contains empty pattern")
		}
	}

	return nil
}

// ConfigDir returns the path to the .vibeguard directory.
func ConfigDir(projectPath string) string {
	return filepath.Join(projectPath, ".vibeguard")
}

// ConfigPath returns the path to .vibeguard/config.json.
func ConfigPath(projectPath string) string {
	return filepath.Join(ConfigDir(projectPath), "config.json")
}

// LoadConfig reads .vibeguard/config.json, falling back to defaults if not found.
func LoadConfig(projectPath string) (*Config, error) {
	cfgFile := ConfigPath(projectPath)
	data, err := os.ReadFile(cfgFile)
	if os.IsNotExist(err) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("malformed configuration file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// CreateDefaultConfig writes the default configuration file to .vibeguard/config.json.
func CreateDefaultConfig(projectPath string) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(DefaultConfig(), "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}

// SaveConfig writes a specific configuration to .vibeguard/config.json.
func SaveConfig(projectPath string, cfg *Config) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}
