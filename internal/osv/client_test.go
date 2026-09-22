package osv

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryOSVWithMockServer(t *testing.T) {
	tmpCache := t.TempDir()
	SetCacheDir(tmpCache)
	SetCacheEnabled(true)
	SetOfflineMode(false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockJSON := `{
  "vulns": [
    {
      "id": "GHSA-1234-5678-90ab",
      "summary": "Sample Critical Prototype Pollution",
      "details": "A detailed description of the sample prototype pollution vulnerability.",
      "aliases": ["CVE-2023-99999"],
      "affected": [
        {
          "package": {
            "name": "sample-pkg",
            "ecosystem": "npm"
          },
          "ranges": [
            {
              "type": "SEMVER",
              "events": [
                {"introduced": "0"},
                {"fixed": "2.0.0"}
              ]
            }
          ]
        }
      ],
      "database_specific": {
        "severity": "CRITICAL"
      }
    }
  ]
}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	SetBaseURL(server.URL)
	defer SetBaseURL("")

	// First query: goes to server and populates cache
	vulns, err := QueryOSV("sample-pkg", "1.0.0", "npm")
	if err != nil {
		t.Fatalf("QueryOSV failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	if vulns[0].ID != "GHSA-1234-5678-90ab" {
		t.Errorf("expected GHSA-1234-5678-90ab, got %s", vulns[0].ID)
	}

	// Verify cached
	cached, ok := GetCachedVulns("sample-pkg", "1.0.0", "npm")
	if !ok || len(cached) != 1 {
		t.Errorf("expected cached vulns, got ok=%v, len=%d", ok, len(cached))
	}

	// Enable offline mode: should read from cache successfully
	SetOfflineMode(true)
	offlineVulns, err := QueryOSV("sample-pkg", "1.0.0", "npm")
	if err != nil {
		t.Errorf("expected offline cache read to succeed, got: %v", err)
	}
	if len(offlineVulns) != 1 {
		t.Errorf("expected 1 vuln from offline cache, got %d", len(offlineVulns))
	}

	// Query an uncached package in offline mode: should fail with descriptive error
	_, err = QueryOSV("uncached-pkg", "9.9.9", "npm")
	if err == nil {
		t.Errorf("expected uncached query in offline mode to fail")
	}
}

func TestQueryOSVMalformedJSON(t *testing.T) {
	tmpCache := t.TempDir()
	SetCacheDir(tmpCache)
	SetCacheEnabled(false)
	SetOfflineMode(false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{ "vulns": [invalid json`))
	}))
	defer server.Close()

	SetBaseURL(server.URL)
	defer SetBaseURL("")

	_, err := QueryOSV("malformed-pkg", "1.0.0", "npm")
	if err == nil {
		t.Errorf("expected error on malformed JSON, got nil")
	}
}

func TestQueryOSVHTTPErrors(t *testing.T) {
	statusCodes := []int{
		http.StatusBadRequest,          // 400
		http.StatusTooManyRequests,    // 429
		http.StatusInternalServerError, // 500
	}

	for _, code := range statusCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				w.Write([]byte(`error response`))
			}))
			defer server.Close()

			SetBaseURL(server.URL)
			defer SetBaseURL("")
			SetCacheEnabled(false)

			_, err := QueryOSV("err-pkg", "1.0.0", "npm")
			if err == nil {
				t.Errorf("expected error on HTTP %d, got nil", code)
			}
		})
	}
}

func TestQueryOSVEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	SetBaseURL(server.URL)
	defer SetBaseURL("")
	SetCacheEnabled(false)

	vulns, err := QueryOSV("clean-pkg", "1.0.0", "npm")
	if err != nil {
		t.Fatalf("expected clean empty response to succeed, got: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestClearCache(t *testing.T) {
	tmpCache := t.TempDir()
	SetCacheDir(tmpCache)
	SetCacheEnabled(true)
	defer SetCacheEnabled(false)

	if err := SaveCachedVulns("test-pkg", "1.0.0", "npm", []Vulnerability{}); err != nil {
		t.Fatalf("failed to save cached vuln: %v", err)
	}

	if err := ClearCache(); err != nil {
		t.Fatalf("ClearCache failed: %v", err)
	}

	_, ok := GetCachedVulns("test-pkg", "1.0.0", "npm")
	if ok {
		t.Errorf("expected cache to be empty after ClearCache")
	}
}
