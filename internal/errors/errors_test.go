package errors

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStructuredErrorJSON(t *testing.T) {
	err := NewStructuredError(ErrInvalidFormat, "INVALID_FORMAT", "Unsupported output format: xml", 3)
	s := err.String()

	if !strings.Contains(s, "VG-E003") {
		t.Errorf("expected VG-E003 in output, got: %s", s)
	}

	var parsed StructuredError
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		t.Fatalf("failed to parse structured error JSON: %v", err)
	}

	if parsed.Error.Code != ErrInvalidFormat {
		t.Errorf("expected code %s, got %s", ErrInvalidFormat, parsed.Error.Code)
	}
	if parsed.Error.ExitCode != 3 {
		t.Errorf("expected exit code 3, got %d", parsed.Error.ExitCode)
	}
}
