package database

import (
	"path/filepath"
	"testing"
)

func TestDatabaseSeedAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, ".vibeguard", "database", "security.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	status := db.Status()
	if status.TotalVulnerabilities < 10 {
		t.Errorf("expected at least 10 seed vulnerabilities, got %d", status.TotalVulnerabilities)
	}

	// Test querying vulnerable package lodash 4.17.20
	vulns := db.Lookup("lodash", "4.17.20", "npm")
	if len(vulns) == 0 {
		t.Errorf("expected vulnerabilities for lodash 4.17.20, got 0")
	}

	// Test querying patched lodash 4.17.21
	patched := db.Lookup("lodash", "4.17.21", "npm")
	if len(patched) != 0 {
		t.Errorf("expected 0 vulnerabilities for lodash 4.17.21, got %d", len(patched))
	}

	// Test querying Flask 2.0.1 (PyPI)
	flaskVulns := db.Lookup("Flask", "2.0.1", "PyPI")
	if len(flaskVulns) == 0 {
		t.Errorf("expected vulnerabilities for Flask 2.0.1, got 0")
	}

	// Test querying unknown package
	unknown := db.Lookup("nonexistent-pkg", "1.0.0", "npm")
	if len(unknown) != 0 {
		t.Errorf("expected 0 vulnerabilities for nonexistent-pkg, got %d", len(unknown))
	}
}

func TestDatabaseImportExport(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "security.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Export to json
	exportPath := filepath.Join(tmpDir, "export.json")
	if err := db.Export(exportPath); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Import from json into new DB
	dbPath2 := filepath.Join(tmpDir, "security2.db")
	db2, err := Open(dbPath2)
	if err != nil {
		t.Fatalf("Open second db failed: %v", err)
	}

	imported, err := db2.ImportFileOrDir(exportPath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if imported < 0 {
		t.Errorf("expected imported count >= 0, got %d", imported)
	}
}
