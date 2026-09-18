package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ProgressBar manages dynamic terminal progress reporting.
type ProgressBar struct {
	width        int
	out          io.Writer
	isTTY        bool
	linesPrinted int
	mu           sync.Mutex
}

// NewProgressBar creates a new progress bar renderer.
func NewProgressBar(width int, out io.Writer) *ProgressBar {
	if width <= 0 {
		width = 20
	}
	if out == nil {
		out = os.Stdout
	}

	isTTY := false
	if f, ok := out.(*os.File); ok {
		stat, err := f.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
			isTTY = true
		}
	}

	return &ProgressBar{
		width: width,
		out:   out,
		isTTY: isTTY,
	}
}

// SetTTY allows explicitly toggling TTY mode (useful for unit tests).
func (p *ProgressBar) SetTTY(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isTTY = enabled
}

// BuildBar constructs the [██████████████░░░░░░] string and percentage.
func (p *ProgressBar) BuildBar(current, total int) (string, int) {
	if total <= 0 {
		total = 1
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}

	pct := (current * 100) / total
	filled := (pct * p.width) / 100
	if filled > p.width {
		filled = p.width
	}
	empty := p.width - filled

	bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", empty) + "]"
	return bar, pct
}

// Render displays the progress bar with up to two description lines.
// Example:
// [██████████████░░░░░░] 70%
// Files: 56/80
// Current: internal/scanner/runner.go
func (p *ProgressBar) Render(current, total int, line1, line2 string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bar, pct := p.BuildBar(current, total)

	lines := []string{
		fmt.Sprintf("%s %d%%", bar, pct),
	}
	if line1 != "" {
		lines = append(lines, line1)
	}
	if line2 != "" {
		lines = append(lines, line2)
	}

	if p.isTTY && p.linesPrinted > 0 {
		// Move cursor up by previously printed lines
		fmt.Fprintf(p.out, "\033[%dA\r", p.linesPrinted)
	}

	for _, l := range lines {
		if p.isTTY {
			// Clear line to end and print
			fmt.Fprintf(p.out, "\033[K%s\n", l)
		} else {
			fmt.Fprintf(p.out, "%s\n", l)
		}
	}

	p.linesPrinted = len(lines)
}

// Finish displays the final 100% completion bar.
// Example:
// [████████████████████] 100%
// Security analysis complete.
func (p *ProgressBar) Finish(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bar := "[" + strings.Repeat("█", p.width) + "]"

	if p.isTTY && p.linesPrinted > 0 {
		fmt.Fprintf(p.out, "\033[%dA\r", p.linesPrinted)
	}

	if p.isTTY {
		fmt.Fprintf(p.out, "\033[K%s 100%%\n", bar)
		if message != "" {
			fmt.Fprintf(p.out, "\033[K\n\033[K%s\n", message)
		}
	} else {
		fmt.Fprintf(p.out, "%s 100%%\n", bar)
		if message != "" {
			fmt.Fprintf(p.out, "\n%s\n", message)
		}
	}

	p.linesPrinted = 0
}

// Reset clears the line counter.
func (p *ProgressBar) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.linesPrinted = 0
}
