package defender

import (
	"errors"
	"strings"
	"testing"
)

func TestIsBlockedByDefenderOrAV(t *testing.T) {
	// 1. Nil error
	rep, blocked := IsBlockedByDefenderOrAV(nil, "scanner.exe")
	if blocked || rep != nil {
		t.Fatalf("expected nil/false for nil error, got blocked=%v", blocked)
	}

	// 2. Unrelated error
	rep, blocked = IsBlockedByDefenderOrAV(errors.New("file not found in directory"), "scanner.exe")
	if blocked || rep != nil {
		t.Fatalf("expected false for generic error, got blocked=%v", blocked)
	}

	// 3. Virus infected Win32 error 225
	virusErr := errors.New("exec: \"vibeguard-scanner.exe\": Operation did not complete successfully because the file contains a virus or potentially unwanted software.")
	rep, blocked = IsBlockedByDefenderOrAV(virusErr, "vibeguard-scanner.exe")
	if !blocked || rep == nil {
		t.Fatalf("expected blocked=true for virus error, got blocked=%v", blocked)
	}
	if rep.Component != "vibeguard-scanner.exe" {
		t.Errorf("expected component 'vibeguard-scanner.exe', got '%s'", rep.Component)
	}
	if !strings.Contains(rep.Reason, "false positive") && !strings.Contains(rep.Reason, "ERROR_VIRUS_INFECTED") {
		t.Errorf("expected virus reason, got '%s'", rep.Reason)
	}
	if len(rep.Remediation) == 0 {
		t.Errorf("expected remediation steps, got 0")
	}

	// 4. Access Denied error
	accessErr := errors.New("fork/exec C:\\Users\\user\\AppData\\Local\\VibeGuard\\scanner.exe: Access is denied.")
	rep, blocked = IsBlockedByDefenderOrAV(accessErr, "C:\\Users\\user\\AppData\\Local\\VibeGuard\\scanner.exe")
	if !blocked || rep == nil {
		t.Fatalf("expected blocked=true for Access Denied error, got blocked=%v", blocked)
	}
	if rep.Component != "scanner.exe" {
		t.Errorf("expected component 'scanner.exe', got '%s'", rep.Component)
	}
	if !strings.Contains(rep.Reason, "Access Denied") {
		t.Errorf("expected Access Denied in reason, got '%s'", rep.Reason)
	}

	// 5. Verify FormatPopupBody
	body := FormatPopupBody(rep)
	if !strings.Contains(body, "VIBEGUARD EXECUTION INTERCEPTED") {
		t.Errorf("expected header in popup body, got:\n%s", body)
	}
	if !strings.Contains(body, rep.Component) {
		t.Errorf("expected component in popup body, got:\n%s", body)
	}
}

func TestDetectActiveSecuritySoftware(t *testing.T) {
	name := DetectActiveSecuritySoftware()
	if strings.TrimSpace(name) == "" {
		t.Errorf("expected non-empty security software name, got empty string")
	}
}
