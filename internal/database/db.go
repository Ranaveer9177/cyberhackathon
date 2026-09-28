package database

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	defaultDBInstance *DB
	defaultDBOnce     sync.Once
	defaultDBMu       sync.Mutex
)

// DB represents an open offline security intelligence database with in-memory index.
type DB struct {
	mu       sync.RWMutex
	filePath string
	dbDir    string
	data     SecurityDatabase
	index    map[string][]*VulnerabilityRecord
}

// DatabaseStatus provides summary statistics for the database.
type DatabaseStatus struct {
	Path                 string    `json:"path"`
	MultiDirPath         string    `json:"multi_dir_path"`
	Active               bool      `json:"active"`
	Version              string    `json:"version"`
	UpdatedAt            time.Time `json:"updated_at"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	TotalPackages        int       `json:"total_packages"`
	Ecosystems           []string  `json:"ecosystems"`
}

// GetDefaultDB returns the singleton instance of the offline security intelligence database.
func GetDefaultDB() *DB {
	defaultDBOnce.Do(func() {
		dbPath := ResolveDatabasePath(".")
		db, err := Open(dbPath)
		if err != nil {
			// Fallback to in-memory seed database
			seed := GetSeedDatabase()
			db = &DB{
				filePath: dbPath,
				dbDir:    filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "db"),
				data:     *seed,
				index:    make(map[string][]*VulnerabilityRecord),
			}
			db.rebuildIndex()
		}
		defaultDBInstance = db
	})
	return defaultDBInstance
}

// ResetDefaultDB resets the default singleton instance (useful for tests).
func ResetDefaultDB() {
	defaultDBMu.Lock()
	defer defaultDBMu.Unlock()
	defaultDBOnce = sync.Once{}
	defaultDBInstance = nil
}

// ResolveDatabasePath finds the appropriate path for .vibeguard/database/security.db.
func ResolveDatabasePath(baseDir string) string {
	if baseDir == "" {
		baseDir = "."
	}
	return filepath.Join(baseDir, ".vibeguard", "database", "security.db")
}

// Open loads or initializes the security database from the given path.
func Open(path string) (*DB, error) {
	if path == "" {
		path = ResolveDatabasePath(".")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	baseVibeDir := filepath.Dir(filepath.Dir(absPath))
	multiDir := filepath.Join(baseVibeDir, "db")

	db := &DB{
		filePath: absPath,
		dbDir:    multiDir,
		index:    make(map[string][]*VulnerabilityRecord),
	}

	// 1. Try reading existing database file
	if dataBytes, err := os.ReadFile(absPath); err == nil {
		var secDB SecurityDatabase
		if err := json.Unmarshal(dataBytes, &secDB); err == nil {
			db.data = secDB
			db.rebuildIndex()
			return db, nil
		}
	}

	// 2. Try loading from .vibeguard/db/vulnerabilities/ directory if present
	if loadedFromDir, err := loadFromMultiDir(multiDir); err == nil && len(loadedFromDir.Vulnerabilities) > 0 {
		db.data = *loadedFromDir
		db.rebuildIndex()
		_ = db.Save(absPath)
		return db, nil
	}

	// 3. Initialize from bootstrap seed database
	seed := GetSeedDatabase()
	db.data = *seed
	db.rebuildIndex()

	// Persist seed database and folder layout so it is ready for offline scans
	_ = db.Save(absPath)

	return db, nil
}

func loadFromMultiDir(dir string) (*SecurityDatabase, error) {
	vulnDir := filepath.Join(dir, "vulnerabilities")
	if _, err := os.Stat(vulnDir); os.IsNotExist(err) {
		return nil, err
	}

	metaFile := filepath.Join(dir, "metadata", "metadata.json")
	var meta DatabaseMetadata
	if mData, err := os.ReadFile(metaFile); err == nil {
		_ = json.Unmarshal(mData, &meta)
	}

	var vulns []VulnerabilityRecord
	_ = filepath.WalkDir(vulnDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var list []VulnerabilityRecord
		if err := json.Unmarshal(data, &list); err == nil {
			vulns = append(vulns, list...)
			return nil
		}
		var single VulnerabilityRecord
		if err := json.Unmarshal(data, &single); err == nil {
			vulns = append(vulns, single)
		}
		return nil
	})

	if len(vulns) == 0 {
		return nil, fmt.Errorf("no records found in %s", vulnDir)
	}

	return &SecurityDatabase{
		Metadata:        meta,
		Vulnerabilities: vulns,
	}, nil
}

// rebuildIndex must be called with lock held or during init.
func (db *DB) rebuildIndex() {
	db.index = make(map[string][]*VulnerabilityRecord)
	pkgsMap := make(map[string]bool)
	ecoMap := make(map[string]bool)

	for i := range db.data.Vulnerabilities {
		rec := &db.data.Vulnerabilities[i]
		key := makeKey(rec.Ecosystem, rec.Package)
		db.index[key] = append(db.index[key], rec)
		pkgsMap[strings.ToLower(rec.Package)] = true
		if rec.Ecosystem != "" {
			ecoMap[rec.Ecosystem] = true
		}
	}

	var ecosystems []string
	for e := range ecoMap {
		ecosystems = append(ecosystems, e)
	}
	sort.Strings(ecosystems)

	db.data.Metadata.TotalVulnerabilities = len(db.data.Vulnerabilities)
	db.data.Metadata.TotalPackages = len(pkgsMap)
	db.data.Metadata.Ecosystems = ecosystems
	if db.data.Metadata.Version == "" {
		db.data.Metadata.Version = "6.9.0"
	}
	if db.data.Metadata.UpdatedAt.IsZero() {
		db.data.Metadata.UpdatedAt = time.Now()
	}
}

func makeKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + ":" + strings.ToLower(strings.TrimSpace(name))
}

// Save writes the database to .vibeguard/database/security.db and synchronizes .vibeguard/db/ structure.
func (db *DB) Save(path string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if path == "" {
		path = db.filePath
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	db.data.Metadata.UpdatedAt = time.Now()
	dataBytes, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, dataBytes, 0644); err != nil {
		return err
	}

	// Also synchronize .vibeguard/db/ structure:
	// db/
	//   ├── vulnerabilities/
	//   ├── packages/
	//   ├── rules/
	//   └── metadata/
	baseDir := filepath.Dir(dir)
	multiDir := filepath.Join(baseDir, "db")
	_ = db.syncMultiDir(multiDir)

	return nil
}

func (db *DB) syncMultiDir(dir string) error {
	vulnDir := filepath.Join(dir, "vulnerabilities")
	pkgDir := filepath.Join(dir, "packages")
	rulesDir := filepath.Join(dir, "rules")
	metaDir := filepath.Join(dir, "metadata")

	for _, d := range []string{vulnDir, pkgDir, rulesDir, metaDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}

	// 1. Write metadata
	metaBytes, _ := json.MarshalIndent(db.data.Metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(metaDir, "metadata.json"), metaBytes, 0644)

	// 2. Write packages summary
	pkgList := make([]string, 0, len(db.index))
	for k := range db.index {
		pkgList = append(pkgList, k)
	}
	sort.Strings(pkgList)
	pkgBytes, _ := json.MarshalIndent(pkgList, "", "  ")
	_ = os.WriteFile(filepath.Join(pkgDir, "packages.json"), pkgBytes, 0644)

	// 3. Write vulnerabilities summary
	vulnBytes, _ := json.MarshalIndent(db.data.Vulnerabilities, "", "  ")
	_ = os.WriteFile(filepath.Join(vulnDir, "all_vulnerabilities.json"), vulnBytes, 0644)

	// 4. Write rules index
	rulesMeta := map[string]interface{}{
		"semver_matching": "enabled",
		"offline_engine":  "v6.9.0",
		"rule_types":      []string{"range", "semver", "ecosystem", "cve", "ghsa"},
	}
	ruleBytes, _ := json.MarshalIndent(rulesMeta, "", "  ")
	_ = os.WriteFile(filepath.Join(rulesDir, "rules.json"), ruleBytes, 0644)

	return nil
}

// Lookup looks up vulnerabilities for a given package and version from the local database.
func (db *DB) Lookup(name, installedVersion, ecosystem string) []VulnerabilityRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := makeKey(ecosystem, name)
	candidates, ok := db.index[key]
	if !ok {
		// Also try without ecosystem qualifier if ambiguous
		for k, list := range db.index {
			if strings.HasSuffix(k, ":"+strings.ToLower(name)) {
				candidates = append(candidates, list...)
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	var results []VulnerabilityRecord
	for _, cand := range candidates {
		if installedVersion == "" || installedVersion == "unknown" || cand.IsVulnerable(installedVersion) {
			results = append(results, *cand)
		}
	}

	return results
}

type rawOSVVuln struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []rawOSVSeverity       `json:"severity"`
	Affected         []rawOSVAffected       `json:"affected"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type rawOSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type rawOSVAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// ImportRecords inserts or updates vulnerability records into the local database.
func (db *DB) ImportRecords(records []VulnerabilityRecord) (int, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	existingIDs := make(map[string]int)
	for i, v := range db.data.Vulnerabilities {
		existingIDs[v.ID] = i
	}

	importedCount := 0
	for _, rec := range records {
		if rec.ID == "" || rec.Package == "" {
			continue
		}
		if idx, exists := existingIDs[rec.ID]; exists {
			// Update existing record
			db.data.Vulnerabilities[idx] = rec
		} else {
			db.data.Vulnerabilities = append(db.data.Vulnerabilities, rec)
			existingIDs[rec.ID] = len(db.data.Vulnerabilities) - 1
			importedCount++
		}
	}

	db.rebuildIndex()
	return importedCount, nil
}

// ImportOSVData parses OSV JSON data and merges the vulnerabilities into the database.
func (db *DB) ImportOSVData(data []byte) (int, error) {
	// Try parsing as QueryResponse: {"vulns": [...]}
	var qResp struct {
		Vulns []rawOSVVuln `json:"vulns"`
	}
	if err := json.Unmarshal(data, &qResp); err == nil && len(qResp.Vulns) > 0 {
		return db.importOSVVulns(qResp.Vulns)
	}

	// Try parsing as array of rawOSVVuln: [...]
	var vulns []rawOSVVuln
	if err := json.Unmarshal(data, &vulns); err == nil && len(vulns) > 0 {
		return db.importOSVVulns(vulns)
	}

	// Try parsing as single rawOSVVuln: {...}
	var single rawOSVVuln
	if err := json.Unmarshal(data, &single); err == nil && single.ID != "" {
		return db.importOSVVulns([]rawOSVVuln{single})
	}

	// Try parsing as SecurityDatabase export
	var secDB SecurityDatabase
	if err := json.Unmarshal(data, &secDB); err == nil && len(secDB.Vulnerabilities) > 0 {
		return db.ImportRecords(secDB.Vulnerabilities)
	}

	return 0, fmt.Errorf("unrecognized vulnerability data format")
}

func (db *DB) importOSVVulns(vulns []rawOSVVuln) (int, error) {
	var records []VulnerabilityRecord
	for _, v := range vulns {
		for _, aff := range v.Affected {
			var ranges []RangeSpec
			var fixedVersions []string

			for _, r := range aff.Ranges {
				var events []EventSpec
				for _, ev := range r.Events {
					events = append(events, EventSpec{
						Introduced:   ev.Introduced,
						Fixed:        ev.Fixed,
						LastAffected: ev.LastAffected,
					})
					if ev.Fixed != "" {
						fixedVersions = append(fixedVersions, ev.Fixed)
					}
				}
				ranges = append(ranges, RangeSpec{
					Type:   r.Type,
					Events: events,
				})
			}

			sevStr := "MEDIUM"
			if v.DatabaseSpecific != nil {
				if s, ok := v.DatabaseSpecific["severity"].(string); ok && s != "" {
					sevStr = strings.ToUpper(s)
				}
			}

			var cwes []string
			if v.DatabaseSpecific != nil {
				if cList, ok := v.DatabaseSpecific["cwe"].([]interface{}); ok {
					for _, c := range cList {
						if cs, ok := c.(string); ok {
							cwes = append(cwes, cs)
						}
					}
				}
			}

			cvssScore := 0.0
			cvssVector := ""
			for _, se := range v.Severity {
				if strings.Contains(strings.ToUpper(se.Type), "CVSS") {
					cvssVector = se.Score
					break
				}
			}

			records = append(records, VulnerabilityRecord{
				ID:               v.ID,
				Package:          aff.Package.Name,
				Ecosystem:        aff.Package.Ecosystem,
				AffectedVersions: aff.Versions,
				FixedVersions:    fixedVersions,
				Severity:         sevStr,
				CWE:              cwes,
				CVSS:             cvssVector,
				CVSSScore:        cvssScore,
				Aliases:          v.Aliases,
				Summary:          v.Summary,
				Description:      v.Details,
				Ranges:           ranges,
			})
		}
	}

	return db.ImportRecords(records)
}

// ImportFileOrDir imports records from a JSON file or recursively from all JSON files in a directory.
func (db *DB) ImportFileOrDir(targetPath string) (int, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return 0, err
	}

	if !info.IsDir() {
		data, err := os.ReadFile(targetPath)
		if err != nil {
			return 0, err
		}
		count, err := db.ImportOSVData(data)
		if err == nil {
			_ = db.Save("")
		}
		return count, err
	}

	totalImported := 0
	err = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if count, impErr := db.ImportOSVData(data); impErr == nil {
			totalImported += count
		}
		return nil
	})

	if totalImported > 0 {
		_ = db.Save("")
	}
	return totalImported, err
}

// Export writes the database in JSON format to the target output path.
func (db *DB) Export(outputPath string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	dataBytes, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, dataBytes, 0644)
}

// Status returns current database statistics and operational status.
func (db *DB) Status() DatabaseStatus {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return DatabaseStatus{
		Path:                 db.filePath,
		MultiDirPath:         db.dbDir,
		Active:               true,
		Version:              db.data.Metadata.Version,
		UpdatedAt:            db.data.Metadata.UpdatedAt,
		TotalVulnerabilities: db.data.Metadata.TotalVulnerabilities,
		TotalPackages:        db.data.Metadata.TotalPackages,
		Ecosystems:           db.data.Metadata.Ecosystems,
	}
}
