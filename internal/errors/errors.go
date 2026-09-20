package errors

import (
	"encoding/json"
	"fmt"
	"os"
)

type ErrorCode string

const (
	ErrInvalidArgument   ErrorCode = "VG-E001"
	ErrPathNotFound      ErrorCode = "VG-E002"
	ErrInvalidFormat     ErrorCode = "VG-E003"
	ErrInvalidConfig     ErrorCode = "VG-E004"
	ErrScannerError      ErrorCode = "VG-E005"
	ErrOSVUnavailable    ErrorCode = "VG-E006"
	ErrGitError          ErrorCode = "VG-E007"
	ErrInstallationError ErrorCode = "VG-E008"
)

type ErrorDetail struct {
	Code     ErrorCode `json:"code"`
	Type     string    `json:"type"`
	Message  string    `json:"message"`
	ExitCode int       `json:"exit_code"`
}

type StructuredError struct {
	Error ErrorDetail `json:"error"`
}

func (e *StructuredError) String() string {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error %s: %s", e.Error.Code, e.Error.Message)
	}
	return string(b)
}

func NewStructuredError(code ErrorCode, errType, message string, exitCode int) *StructuredError {
	return &StructuredError{
		Error: ErrorDetail{
			Code:     code,
			Type:     errType,
			Message:  message,
			ExitCode: exitCode,
		},
	}
}

// PrintAndExit prints the error (structured JSON if asJSON is true, otherwise formatted text) and exits.
func PrintAndExit(err *StructuredError, asJSON bool) {
	if asJSON {
		fmt.Fprintln(os.Stderr, err.String())
	} else {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error.Message)
	}
	os.Exit(err.Error.ExitCode)
}
