//go:build !windows
// +build !windows

package defender

import (
	"fmt"
	"os"
)

type BlockReport struct {
	Blocked         bool     `json:"blocked"`
	Component       string   `json:"component"`
	DetectedBlocker string   `json:"detected_blocker"`
	Reason          string   `json:"reason"`
	Details         string   `json:"details"`
	Remediation     []string `json:"remediation"`
}

func IsBlockedByDefenderOrAV(err error, componentPath string) (*BlockReport, bool) {
	return nil, false
}

func DetectActiveSecuritySoftware() string {
	return "System Security Policy"
}

func ShowBlockPopup(rep *BlockReport) {
	if rep == nil || !rep.Blocked {
		return
	}
	PrintTerminalAlert(rep)
}

func ShowBlockPopupWithTimeout(rep *BlockReport, timeoutSeconds int) {
	ShowBlockPopup(rep)
}

func FormatPopupBody(rep *BlockReport) string {
	return fmt.Sprintf("Blocked Component: %s\nReason: %s", rep.Component, rep.Reason)
}

func PrintTerminalAlert(rep *BlockReport) {
	fmt.Fprintf(os.Stderr, "[VibeGuard Alert] %s blocked: %s\n", rep.Component, rep.Reason)
}

func IsNonInteractive() bool {
	return true
}

func GetVibeGuardHomeDir() string {
	return os.Getenv("HOME")
}
