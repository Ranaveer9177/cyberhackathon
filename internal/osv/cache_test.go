package osv

import (
	"testing"
	"time"
)

func TestCacheTTLAndIntegrity(t *testing.T) {
	tmpCache := t.TempDir()
	SetCacheDir(tmpCache)
	SetCacheEnabled(true)
	SetOfflineMode(false)
	SetCacheTTL(100 * time.Millisecond)
	defer SetCacheTTL(24 * time.Hour)

	sampleVulns := []Vulnerability{
		{ID: "TEST-001", Summary: "Sample Vuln"},
	}

	// 1. Save to cache
	err := SaveCachedVulns("test-lib", "1.0.0", "npm", sampleVulns)
	if err != nil {
		t.Fatalf("failed to save cached vulns: %v", err)
	}

	// 2. Immediate read: fresh, should succeed
	vulns, ok := GetCachedVulns("test-lib", "1.0.0", "npm")
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected fresh cache hit, got ok=%v, len=%d", ok, len(vulns))
	}

	// 3. Sleep past TTL: should expire
	time.Sleep(150 * time.Millisecond)
	_, ok = GetCachedVulns("test-lib", "1.0.0", "npm")
	if ok {
		t.Errorf("expected cache to be expired past TTL")
	}

	// 4. Stale read should still succeed for offline/fallback resilience
	stale, ok := GetStaleCachedVulns("test-lib", "1.0.0", "npm")
	if !ok || len(stale) != 1 {
		t.Fatalf("expected stale cache hit, got ok=%v, len=%d", ok, len(stale))
	}

	// 5. Offline mode overrides TTL expiration
	SetOfflineMode(true)
	offlineVulns, ok := GetCachedVulns("test-lib", "1.0.0", "npm")
	if !ok || len(offlineVulns) != 1 {
		t.Errorf("expected offline mode to permit expired cache, got ok=%v", ok)
	}
	SetOfflineMode(false)

	// 6. Integrity check: wrong package name returns false
	_, ok = GetCachedVulns("malicious-tampered", "1.0.0", "npm")
	if ok {
		t.Errorf("expected cache lookup for mismatched package to fail")
	}
}
