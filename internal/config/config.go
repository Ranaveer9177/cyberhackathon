package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	}
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
		return nil, err
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
