//go:build windows
// +build windows

package defender

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32DLL   = syscall.NewLazyDLL("user32.dll")
	messageBoxW = user32DLL.NewProc("MessageBoxW")
)

const (
	MB_OK          = 0x00000000
	MB_OKCANCEL    = 0x00000001
	MB_ICONWARNING = 0x00000030
	MB_SYSTEMMODAL = 0x00001000
)

// BlockReport holds details when VibeGuard or its scanner is intercepted by security software.
type BlockReport struct {
	Blocked         bool     `json:"blocked"`
	Component       string   `json:"component"`
	DetectedBlocker string   `json:"detected_blocker"`
	Reason          string   `json:"reason"`
	Details         string   `json:"details"`
	Remediation     []string `json:"remediation"`
}

// IsBlockedByDefenderOrAV evaluates whether a process or file error was caused by Windows Defender or security software.
func IsBlockedByDefenderOrAV(err error, componentPath string) (*BlockReport, bool) {
	if err == nil {
		return nil, false
	}

	errStr := strings.ToLower(err.Error())

	// Common Windows Defender / Antivirus error signatures
	isVirusError := strings.Contains(errStr, "virus") ||
		strings.Contains(errStr, "potentially unwanted software") ||
		strings.Contains(errStr, "operation did not complete successfully") ||
		strings.Contains(errStr, "0x800700e1") ||
		strings.Contains(errStr, "225")

	isAccessDenied := strings.Contains(errStr, "access is denied") ||
		strings.Contains(errStr, "0xc0000022") ||
		strings.Contains(errStr, "0xc0000005") ||
		strings.Contains(errStr, "exit status 1392") ||
		strings.Contains(errStr, "exit status 1260")

	// Check if file was quarantined/removed when an execution error specifically reports executable not found
	fileMissingPostExec := false
	if componentPath != "" && (strings.Contains(errStr, "cannot find the path") || strings.Contains(errStr, "executable file not found")) {
		if _, statErr := os.Stat(componentPath); os.IsNotExist(statErr) {
			fileMissingPostExec = true
		}
	}

	if !isVirusError && !isAccessDenied && !fileMissingPostExec {
		return nil, false
	}

	blocker := DetectActiveSecuritySoftware()
	compName := filepath.Base(componentPath)
	if compName == "" || compName == "." {
		compName = "VibeGuard Process"
	}

	var reason string
	switch {
	case isVirusError:
		reason = fmt.Sprintf("Executable blocked by %s as a potential false positive (Win32 Error 225: ERROR_VIRUS_INFECTED).", blocker)
	case fileMissingPostExec:
		reason = fmt.Sprintf("File was quarantined or removed by %s during or immediately after execution.", blocker)
	case isAccessDenied:
		reason = fmt.Sprintf("Process execution was denied or terminated by %s / Controlled Folder Access (Access Denied).", blocker)
	default:
		reason = fmt.Sprintf("Process was intercepted or blocked by %s.", blocker)
	}

	remediation := []string{
		"Open Windows Security -> Virus & threat protection -> Protection history.",
		fmt.Sprintf("Locate the recent block entry for '%s'.", compName),
		"If flagged as a false positive, click 'Actions' -> 'Allow on device' or 'Restore'.",
		"To prevent future scan interruptions, add an exclusion folder for:\n   " + GetVibeGuardHomeDir(),
		"Run 'scripts\\windows\\setup.bat' or 'vibeguard defender-check' to verify.",
	}

	rep := &BlockReport{
		Blocked:         true,
		Component:       compName,
		DetectedBlocker: blocker,
		Reason:          reason,
		Details:         err.Error(),
		Remediation:     remediation,
	}

	return rep, true
}

// DetectActiveSecuritySoftware queries Windows Security Center via WMI to identify the active antivirus.
func DetectActiveSecuritySoftware() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`try { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop).displayName } catch { "Windows Defender" }`)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err == nil {
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		var names []string
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed != "" {
				names = append(names, trimmed)
			}
		}
		if len(names) > 0 {
			return strings.Join(names, ", ")
		}
	}

	return "Microsoft Defender Antivirus"
}

// ShowBlockPopup displays a native Windows MessageBox modal pop-up and prints diagnostic text to stderr.
// It waits indefinitely until the user explicitly dismisses or cancels the dialog (clicks OK, Cancel, or [X]).
func ShowBlockPopup(rep *BlockReport) {
	if rep == nil || !rep.Blocked {
		return
	}

	// Always print high-visibility diagnostic banner to stderr
	PrintTerminalAlert(rep)

	// In non-interactive or CI environments, do not trigger GUI modal
	if IsNonInteractive() {
		return
	}

	title := "VibeGuard v5.1 Security Alert — Execution Blocked"
	body := FormatPopupBody(rep)

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	bodyPtr, _ := syscall.UTF16PtrFromString(body)
	flags := uintptr(MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL)

	_, _, _ = messageBoxW.Call(0, uintptr(unsafe.Pointer(bodyPtr)), uintptr(unsafe.Pointer(titlePtr)), flags)
}

// ShowBlockPopupWithTimeout is kept for backward compatibility; it delegates directly to ShowBlockPopup
// waiting indefinitely until the user dismisses or cancels it.
func ShowBlockPopupWithTimeout(rep *BlockReport, _ int) {
	ShowBlockPopup(rep)
}

// FormatPopupBody creates the text displayed inside the native Windows MessageBox.
func FormatPopupBody(rep *BlockReport) string {
	var sb strings.Builder
	sb.WriteString("⚠️  VIBEGUARD EXECUTION INTERCEPTED / BLOCKED\n\n")
	sb.WriteString(fmt.Sprintf("Blocked Component:  %s\n", rep.Component))
	sb.WriteString(fmt.Sprintf("Detected Blocker:   %s\n", rep.DetectedBlocker))
	sb.WriteString(fmt.Sprintf("Reason:             %s\n\n", rep.Reason))
	sb.WriteString(fmt.Sprintf("Raw System Detail:  %s\n\n", rep.Details))
	sb.WriteString("--------------------------------------------------\n")
	sb.WriteString("REMEDIATION STEPS TO RESTORE VIBEGUARD:\n")
	for i, step := range rep.Remediation {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
	}
	sb.WriteString("--------------------------------------------------\n")
	sb.WriteString("VibeGuard will fallback to its internal engine if available.")
	return sb.String()
}

// PrintTerminalAlert writes an ASCII terminal box alert to os.Stderr.
func PrintTerminalAlert(rep *BlockReport) {
	fmt.Fprintln(os.Stderr, "\n============================================================")
	fmt.Fprintln(os.Stderr, "       ⚠️  VIBEGUARD SECURITY INTERCEPTION ALERT")
	fmt.Fprintln(os.Stderr, "============================================================")
	fmt.Fprintf(os.Stderr, "Blocked Component:  %s\n", rep.Component)
	fmt.Fprintf(os.Stderr, "Detected Blocker:   %s\n", rep.DetectedBlocker)
	fmt.Fprintf(os.Stderr, "Block Reason:       %s\n", rep.Reason)
	fmt.Fprintf(os.Stderr, "System Detail:      %s\n", rep.Details)
	fmt.Fprintln(os.Stderr, "------------------------------------------------------------")
	fmt.Fprintln(os.Stderr, "Recommended Remediation:")
	for i, step := range rep.Remediation {
		fmt.Fprintf(os.Stderr, "  [%d] %s\n", i+1, step)
	}
	fmt.Fprintln(os.Stderr, "============================================================")
	fmt.Fprintln(os.Stderr)
}

// IsNonInteractive checks if the environment is headless or non-interactive.
func IsNonInteractive() bool {
	if os.Getenv("VIBEGUARD_NON_INTERACTIVE") == "1" {
		return true
	}
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		return true
	}
	return false
}

// GetVibeGuardHomeDir returns %LOCALAPPDATA%\VibeGuard.
func GetVibeGuardHomeDir() string {
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		return filepath.Join(la, "VibeGuard")
	}
	if up := os.Getenv("USERPROFILE"); up != "" {
		return filepath.Join(up, "AppData", "Local", "VibeGuard")
	}
	return "C:\\Users\\Default\\AppData\\Local\\VibeGuard"
}
