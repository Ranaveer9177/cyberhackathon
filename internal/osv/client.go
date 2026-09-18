package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DependencyInfo struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

type VulnResult struct {
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	SourceFile       string
	Vulnerabilities  []Vulnerability
}

func QueryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	reqData := QueryRequest{
		Version: version,
		Package: Package{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}
	if version == "unknown" {
		reqData.Version = ""
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	return queryResp.Vulns, nil
}

type OSVProgressFunc func(current, total int)

// CheckAllDependencies queries OSV for all dependencies, returning results.
func CheckAllDependencies(deps []DependencyInfo) []VulnResult {
	results, _ := CheckAllDependenciesWithProgress(deps, nil)
	return results
}

// CheckAllDependenciesWithStatus queries OSV and returns an error if all lookups failed due to network/API outage.
func CheckAllDependenciesWithStatus(deps []DependencyInfo) ([]VulnResult, error) {
	return CheckAllDependenciesWithProgress(deps, nil)
}

// CheckAllDependenciesWithProgress queries OSV for dependencies with real-time progress callbacks.
func CheckAllDependenciesWithProgress(deps []DependencyInfo, progress OSVProgressFunc) ([]VulnResult, error) {
	var results []VulnResult
	var lastErr error
	successCount := 0
	total := len(deps)

	ecosystemMap := map[string]string{
		"Go":        "Go",
		"npm":       "npm",
		"PyPI":      "PyPI",
		"crates.io": "crates.io",
	}

	for idx, d := range deps {
		eco, ok := ecosystemMap[d.Ecosystem]
		if !ok {
			eco = d.Ecosystem
		}

		vulns, err := QueryOSV(d.Name, d.Version, eco)
		if progress != nil {
			progress(idx+1, total)
		}
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
		if len(vulns) == 0 {
			continue
		}

		results = append(results, VulnResult{
			PackageName:      d.Name,
			InstalledVersion: d.Version,
			Ecosystem:        eco,
			SourceFile:       d.SourceFile,
			Vulnerabilities:  vulns,
		})
	}

	if len(deps) > 0 && successCount == 0 && lastErr != nil {
		return results, lastErr
	}

	return results, nil
}
