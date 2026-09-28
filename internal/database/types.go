package database

import (
	"time"
)

// VulnerabilityRecord represents a structured security vulnerability in the local database.
type VulnerabilityRecord struct {
	ID               string      `json:"id"`
	Package          string      `json:"package"`
	Ecosystem        string      `json:"ecosystem"`
	AffectedVersions []string    `json:"affected_versions"`
	FixedVersions    []string    `json:"fixed_versions"`
	Severity         string      `json:"severity"`
	CWE              []string    `json:"cwe,omitempty"`
	CVSS             string      `json:"cvss,omitempty"`
	CVSSScore        float64     `json:"cvss_score,omitempty"`
	Aliases          []string    `json:"aliases,omitempty"`
	Summary          string      `json:"summary"`
	Description      string      `json:"description,omitempty"`
	Ranges           []RangeSpec `json:"ranges,omitempty"`
}

// RangeSpec defines version range boundaries for semver comparison.
type RangeSpec struct {
	Type   string      `json:"type"` // "SEMVER", "ECOSYSTEM", "GIT"
	Events []EventSpec `json:"events"`
}

// EventSpec defines introduced, fixed, or last_affected version limits.
type EventSpec struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// DatabaseMetadata contains information about the local offline intelligence database.
type DatabaseMetadata struct {
	Version              string    `json:"version"`
	UpdatedAt            time.Time `json:"updated_at"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	TotalPackages        int       `json:"total_packages"`
	Ecosystems           []string  `json:"ecosystems"`
}

// SecurityDatabase represents the structured local database stored at .vibeguard/database/security.db.
type SecurityDatabase struct {
	Metadata        DatabaseMetadata      `json:"metadata"`
	Vulnerabilities []VulnerabilityRecord `json:"vulnerabilities"`
}
