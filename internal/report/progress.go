package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
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

// LiveProgress provides dynamic terminal progress reporting showing live percentage
// and estimated time to completion without a progress bar.
type LiveProgress struct {
	out       io.Writer
	isTTY     bool
	startTime time.Time
	prefix    string
	lastLen   int
	mu        sync.Mutex
}

// NewLiveProgress creates a new live percentage progress indicator.
func NewLiveProgress(prefix string, out io.Writer) *LiveProgress {
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
	if os.Getenv("CI") != "" || os.Getenv("VIBEGUARD_NON_INTERACTIVE") != "" {
		isTTY = false
	}
	return &LiveProgress{
		out:       out,
		isTTY:     isTTY,
		startTime: time.Now(),
		prefix:    prefix,
	}
}

// SetTTY enables or disables TTY formatting (useful in tests).
func (lp *LiveProgress) SetTTY(enabled bool) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	lp.isTTY = enabled
}

// FormatProgress builds the live percentage and ETA string without a progress bar.
func (lp *LiveProgress) FormatProgress(current, total int) (string, int) {
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
	elapsed := time.Since(lp.startTime)

	var etaStr string
	if current > 0 && current < total {
		rate := float64(current) / elapsed.Seconds()
		if rate > 0 {
			remaining := float64(total-current) / rate
			if remaining < 0.1 {
				etaStr = "< 0.1s"
			} else if remaining < 60 {
				etaStr = fmt.Sprintf("%.1fs", remaining)
			} else {
				etaStr = fmt.Sprintf("%dm %ds", int(remaining)/60, int(remaining)%60)
			}
		} else {
			etaStr = "calculating..."
		}
	} else if current >= total {
		etaStr = "finishing..."
	} else {
		etaStr = "calculating..."
	}

	line := fmt.Sprintf("   %s: %d%% (%d/%d) | Est. time remaining: %s", lp.prefix, pct, current, total, etaStr)
	return line, pct
}

// Update renders the live percentage and estimated time remaining without a progress bar.
func (lp *LiveProgress) Update(current, total int) {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	line, _ := lp.FormatProgress(current, total)

	if lp.isTTY {
		pad := ""
		if len(line) < lp.lastLen {
			pad = strings.Repeat(" ", lp.lastLen-len(line))
		}
		lp.lastLen = len(line)
		fmt.Fprintf(lp.out, "\r%s%s", line, pad)
	}
}

// Clear removes the live progress line from the terminal.
func (lp *LiveProgress) Clear() {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	if lp.isTTY && lp.lastLen > 0 {
		fmt.Fprintf(lp.out, "\r%s\r", strings.Repeat(" ", lp.lastLen+5))
		lp.lastLen = 0
	}
}
