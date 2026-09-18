package gate

import (
	"testing"
)

func TestEvaluateGate(t *testing.T) {
	tests := []struct {
		name         string
		critical     int
		high         int
		expectedStat string
		expectedCode int
	}{
		{
			name:         "High findings only -> BLOCKED",
			critical:     0,
			high:         5,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "One critical finding -> BLOCKED",
			critical:     1,
			high:         0,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Multiple critical findings -> BLOCKED",
			critical:     4,
			high:         3,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Clean scan -> PASSED",
			critical:     0,
			high:         0,
			expectedStat: "PASSED",
			expectedCode: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateGate(tc.critical, tc.high)
			if res.Status != tc.expectedStat {
				t.Errorf("expected status %s, got %s", tc.expectedStat, res.Status)
			}
			if res.ExitCode != tc.expectedCode {
				t.Errorf("expected exit code %d, got %d", tc.expectedCode, res.ExitCode)
			}
		})
	}
}

func TestEvaluateGateWithPolicy(t *testing.T) {
	// Only block on critical: high should pass
	res := EvaluateGateWithPolicy(0, 5, 2, 1, []string{"critical"})
	if res.Status != "PASSED" || res.ExitCode != 0 {
		t.Errorf("expected PASSED when blocking only on critical, got %s", res.Status)
	}

	// Block on medium: 1 medium should block
	res = EvaluateGateWithPolicy(0, 0, 1, 0, []string{"critical", "high", "medium"})
	if res.Status != "BLOCKED" || res.ExitCode != 1 {
		t.Errorf("expected BLOCKED when blocking on medium, got %s", res.Status)
	}
}
