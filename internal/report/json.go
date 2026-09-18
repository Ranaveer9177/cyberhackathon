package report

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func WriteJSONReport(r *Report, outputPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		absPath = filepath.Clean(outputPath)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(absPath, data, 0644)
}
