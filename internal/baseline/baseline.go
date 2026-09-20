package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/scanner"
)

type Suppression struct {
	RuleID  string `json:"rule_id"`
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"` // YYYY-MM-DD
}

type BaselineFile struct {
	Suppressions []Suppression `json:"suppressions"`
}

// LoadBaseline loads suppression entries from .vibeguard/baseline.json.
func LoadBaseline(projectRoot string) ([]Suppression, error) {
	baselinePath := filepath.Join(projectRoot, ".vibeguard", "baseline.json")
	data, err := os.ReadFile(baselinePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("malformed baseline file %s: file is empty", baselinePath)
	}

	// Support either a top-level array or an object with "suppressions"
	var list []Suppression
	if err := json.Unmarshal(data, &list); err == nil {
		return validateSuppressions(list, baselinePath)
	}

	var bf BaselineFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("malformed baseline file %s: %w", baselinePath, err)
	}
	return validateSuppressions(bf.Suppressions, baselinePath)
}

func validateSuppressions(list []Suppression, baselinePath string) ([]Suppression, error) {
	for i, sup := range list {
		if sup.RuleID == "" && sup.File == "" {
			return nil, fmt.Errorf("malformed baseline entry at index %d in %s: must specify rule_id or file", i, baselinePath)
		}
		if sup.Expires != "" {
			if _, err := time.Parse("2006-01-02", sup.Expires); err != nil {
				return nil, fmt.Errorf("malformed baseline entry at index %d in %s: invalid expiration format %q (expected YYYY-MM-DD)", i, baselinePath, sup.Expires)
			}
		}
	}
	return list, nil
}

// FilterSuppressedFindings removes active findings that match an unexpired suppression.
func FilterSuppressedFindings(findings []scanner.Finding, suppressions []Suppression) (active []scanner.Finding, suppressedCount int) {
	if len(suppressions) == 0 {
		return findings, 0
	}

	now := time.Now()

	for _, f := range findings {
		isSuppressed := false
		fFile := filepath.ToSlash(filepath.Clean(f.File))

		for _, sup := range suppressions {
			supFile := filepath.ToSlash(filepath.Clean(sup.File))
			if sup.RuleID != "" && sup.RuleID != f.ID && sup.RuleID != f.Title {
				continue
			}

			if supFile != "" && !strings.HasSuffix(fFile, supFile) && supFile != fFile {
				continue
			}

			if sup.Line > 0 && f.Line > 0 && sup.Line != f.Line {
				continue
			}

			// Check expiry
			if sup.Expires != "" {
				expTime, err := time.Parse("2006-01-02", sup.Expires)
				if err == nil && now.After(expTime) {
					// Expired: do not suppress
					continue
				}
			}

			isSuppressed = true
			break
		}

		if isSuppressed {
			suppressedCount++
		} else {
			active = append(active, f)
		}
	}

	return active, suppressedCount
}
