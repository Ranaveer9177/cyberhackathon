package integration

import (
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
)

func TestEndToEndDependencyDetection(t *testing.T) {
	// Test against the fixtures in tests/dependencies
	fixtureDir, err := filepath.Abs("../dependencies")
	if err != nil {
		t.Fatalf("failed to get fixture path: %v", err)
	}

	deps, err := dependencies.DetectDependencies(fixtureDir)
	if err != nil {
		t.Fatalf("DetectDependencies returned error: %v", err)
	}

	if len(deps) == 0 {
		t.Errorf("expected dependencies to be discovered in fixture dir, got 0")
	}

	// Verify risk score calculation with mock findings
	mockFindings := []risk.FindingInfo{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
	}
	score := risk.CalculateScore(mockFindings)
	gateRes := gate.EvaluateGate(score.CriticalCount, score.HighCount)

	if gateRes.Status != "BLOCKED" || gateRes.ExitCode != 1 {
		t.Errorf("expected gate to BLOCK with exit code 1, got %s (%d)", gateRes.Status, gateRes.ExitCode)
	}
}
