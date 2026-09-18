package risk

import (
	"testing"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name          string
		findings      []FindingInfo
		expectedScore int
		expectedCrit  int
		expectedHigh  int
	}{
		{
			name:          "Clean project",
			findings:      []FindingInfo{},
			expectedScore: 100,
			expectedCrit:  0,
			expectedHigh:  0,
		},
		{
			name: "Single critical finding",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
			},
			expectedScore: 85, // 100 - 15
			expectedCrit:  1,
			expectedHigh:  0,
		},
		{
			name: "Mixed severities",
			findings: []FindingInfo{
				{Severity: "CRITICAL"}, // -15
				{Severity: "HIGH"},     // -8
				{Severity: "MEDIUM"},   // -3
				{Severity: "LOW"},      // -1
			},
			expectedScore: 73, // 100 - 27
			expectedCrit:  1,
			expectedHigh:  1,
		},
		{
			name: "Heavily vulnerable floor at 0",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
			},
			expectedScore: 0,
			expectedCrit:  7,
			expectedHigh:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := CalculateScore(tc.findings)
			if res.Score != tc.expectedScore {
				t.Errorf("expected score %d, got %d", tc.expectedScore, res.Score)
			}
			if res.CriticalCount != tc.expectedCrit {
				t.Errorf("expected %d critical, got %d", tc.expectedCrit, res.CriticalCount)
			}
			if res.HighCount != tc.expectedHigh {
				t.Errorf("expected %d high, got %d", tc.expectedHigh, res.HighCount)
			}
		})
	}
}
