package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildBar(t *testing.T) {
	pb := NewProgressBar(20, nil)

	// 0%
	bar, pct := pb.BuildBar(0, 100)
	if pct != 0 {
		t.Errorf("expected 0%%, got %d%%", pct)
	}
	if bar != "[░░░░░░░░░░░░░░░░░░░░]" {
		t.Errorf("unexpected bar: %s", bar)
	}

	// 70%
	bar, pct = pb.BuildBar(70, 100)
	if pct != 70 {
		t.Errorf("expected 70%%, got %d%%", pct)
	}
	if bar != "[██████████████░░░░░░]" {
		t.Errorf("unexpected bar for 70%%: %s", bar)
	}

	// 100%
	bar, pct = pb.BuildBar(100, 100)
	if pct != 100 {
		t.Errorf("expected 100%%, got %d%%", pct)
	}
	if bar != "[████████████████████]" {
		t.Errorf("unexpected bar for 100%%: %s", bar)
	}
}

func TestProgressBarRender(t *testing.T) {
	var buf bytes.Buffer
	pb := NewProgressBar(20, &buf)
	pb.SetTTY(false)

	pb.Render(56, 80, "Files: 56/80", "Current: internal/scanner/runner.go")

	output := buf.String()
	if !strings.Contains(output, "70%") {
		t.Errorf("expected 70%% in output, got: %s", output)
	}
	if !strings.Contains(output, "Files: 56/80") {
		t.Errorf("expected 'Files: 56/80' in output, got: %s", output)
	}
	if !strings.Contains(output, "Current: internal/scanner/runner.go") {
		t.Errorf("expected 'Current: internal/scanner/runner.go' in output, got: %s", output)
	}
}

func TestProgressBarFinish(t *testing.T) {
	var buf bytes.Buffer
	pb := NewProgressBar(20, &buf)
	pb.SetTTY(false)

	pb.Finish("Security analysis complete.")

	output := buf.String()
	if !strings.Contains(output, "100%") {
		t.Errorf("expected 100%% in output, got: %s", output)
	}
	if !strings.Contains(output, "Security analysis complete.") {
		t.Errorf("expected message in output, got: %s", output)
	}
}
