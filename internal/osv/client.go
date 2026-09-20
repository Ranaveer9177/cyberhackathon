package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
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

// defaultHTTPClient reuses TCP connections and enables HTTP keep-alive connection pooling
var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	},
}

func QueryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	// 1. Check local disk cache first
	if cached, ok := GetCachedVulns(name, version, ecosystem); ok {
		return cached, nil
	}

	cacheMu.RLock()
	isOffline := offlineMode
	endpoint := customBaseURL
	cacheMu.RUnlock()

	if isOffline {
		return nil, fmt.Errorf("OSV offline: package %s@%s not in local cache", name, version)
	}

	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/query"
	}

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient.Do(req)
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

	// 2. Save result into cache
	_ = SaveCachedVulns(name, version, ecosystem, queryResp.Vulns)

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

// CheckAllDependenciesWithProgress queries OSV concurrently with pooled workers and live progress callbacks.
func CheckAllDependenciesWithProgress(deps []DependencyInfo, progress OSVProgressFunc) ([]VulnResult, error) {
	total := len(deps)
	if total == 0 {
		return nil, nil
	}

	ecosystemMap := map[string]string{
		"Go":        "Go",
		"npm":       "npm",
		"PyPI":      "PyPI",
		"crates.io": "crates.io",
	}

	type depJob struct {
		index int
		dep   DependencyInfo
		eco   string
	}

	// Channel for jobs and pre-allocated results slice for deterministic ordering
	jobs := make(chan depJob, total)
	orderedResults := make([]*VulnResult, total)

	var (
		completedCount int64
		successCount   int64
		firstErrMu     sync.Mutex
		lastErr        error
		wg             sync.WaitGroup
	)

	// Concurrency level: min(10, total)
	numWorkers := 10
	if total < numWorkers {
		numWorkers = total
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				vulns, err := QueryOSV(job.dep.Name, job.dep.Version, job.eco)
				done := int(atomic.AddInt64(&completedCount, 1))
				if progress != nil {
					progress(done, total)
				}

				if err != nil {
					firstErrMu.Lock()
					lastErr = err
					firstErrMu.Unlock()
					continue
				}

				atomic.AddInt64(&successCount, 1)
				if len(vulns) > 0 {
					orderedResults[job.index] = &VulnResult{
						PackageName:      job.dep.Name,
						InstalledVersion: job.dep.Version,
						Ecosystem:        job.eco,
						SourceFile:       job.dep.SourceFile,
						Vulnerabilities:  vulns,
					}
				}
			}
		}()
	}

	// Enqueue all jobs
	for idx, d := range deps {
		eco, ok := ecosystemMap[d.Ecosystem]
		if !ok {
			eco = d.Ecosystem
		}
		jobs <- depJob{index: idx, dep: d, eco: eco}
	}
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()

	// If all lookups failed due to network outage, report the error
	if total > 0 && atomic.LoadInt64(&successCount) == 0 && lastErr != nil {
		return nil, lastErr
	}

	// Collect non-nil results in original order
	var results []VulnResult
	for _, res := range orderedResults {
		if res != nil {
			results = append(results, *res)
		}
	}

	return results, nil
}
