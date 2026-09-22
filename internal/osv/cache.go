package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	cacheMu      sync.RWMutex
	cacheEnabled = true
	offlineMode  = false
	customBaseURL = ""
	cacheDir     = filepath.Join(".vibeguard", "cache", "osv")
)

type CachedRecord struct {
	Package         string          `json:"package"`
	Version         string          `json:"version"`
	Ecosystem       string          `json:"ecosystem"`
	Timestamp       time.Time       `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// SetCacheDir sets the base directory for OSV response caching.
func SetCacheDir(dir string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cacheDir = dir
}

// SetCacheEnabled toggles OSV disk caching.
func SetCacheEnabled(enabled bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cacheEnabled = enabled
}

// SetOfflineMode enables offline cache-only OSV resolution.
func SetOfflineMode(offline bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	offlineMode = offline
}

// IsOfflineMode returns true if offline cache-only mode is active.
func IsOfflineMode() bool {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return offlineMode
}

// ClearCache purges the local OSV cache directory for refreshing data.
func ClearCache() error {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	return os.RemoveAll(cacheDir)
}

// SetBaseURL allows overriding the OSV API endpoint for unit testing.
func SetBaseURL(url string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	customBaseURL = url
}

func getCacheKey(ecosystem, name, version string) string {
	h := sha256.New()
	h.Write([]byte(ecosystem + ":" + name + ":" + version))
	return hex.EncodeToString(h.Sum(nil))[:24] + ".json"
}

// GetCachedVulns retrieves cached vulnerabilities for a package if present.
func GetCachedVulns(name, version, ecosystem string) ([]Vulnerability, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	if !cacheEnabled && !offlineMode {
		return nil, false
	}

	key := getCacheKey(ecosystem, name, version)
	filePath := filepath.Join(cacheDir, key)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	var rec CachedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}

	return rec.Vulnerabilities, true
}

// SaveCachedVulns stores query results to the local disk cache.
func SaveCachedVulns(name, version, ecosystem string, vulns []Vulnerability) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if !cacheEnabled {
		return nil
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}

	rec := CachedRecord{
		Package:         name,
		Version:         version,
		Ecosystem:       ecosystem,
		Timestamp:       time.Now(),
		Vulnerabilities: vulns,
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}

	key := getCacheKey(ecosystem, name, version)
	filePath := filepath.Join(cacheDir, key)
	return os.WriteFile(filePath, data, 0644)
}
