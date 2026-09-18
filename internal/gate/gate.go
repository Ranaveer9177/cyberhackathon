package gate

import (
	"fmt"
	"strings"
)

type GateResult struct {
	Status   string // "PASSED" or "BLOCKED"
	ExitCode int
	Reason   string
}

// EvaluateGate evaluates deployment status blocking on critical and high severity findings.
func EvaluateGate(criticalCount, highCount int) GateResult {
	return EvaluateGateWithPolicy(criticalCount, highCount, 0, 0, []string{"critical", "high"})
}

// EvaluateGateWithPolicy evaluates deployment status against configured blocking levels.
func EvaluateGateWithPolicy(criticalCount, highCount, mediumCount, lowCount int, blockOn []string) GateResult {
	blockMap := make(map[string]bool)
	for _, b := range blockOn {
		blockMap[strings.ToLower(strings.TrimSpace(b))] = true
	}
	if len(blockMap) == 0 {
		blockMap["critical"] = true
		blockMap["high"] = true
	}

	var blockingReasons []string
	if blockMap["critical"] && criticalCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d critical finding(s)", criticalCount))
	}
	if blockMap["high"] && highCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d high-severity finding(s)", highCount))
	}
	if blockMap["medium"] && mediumCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d medium-severity finding(s)", mediumCount))
	}
	if blockMap["low"] && lowCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d low-severity finding(s)", lowCount))
	}

	if len(blockingReasons) > 0 {
		return GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   strings.Join(blockingReasons, " and ") + " detected",
		}
	}

	return GateResult{
		Status:   "PASSED",
		ExitCode: 0,
		Reason:   "No blocking security findings",
	}
}
