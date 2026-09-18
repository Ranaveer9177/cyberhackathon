# VibeGuard Source Structure

The Go application source code is organized following the standard Go project layout:
- `cmd/vibeguard/main.go`: CLI entry point
- `internal/`: Core modules (scanner runner, dependencies, osv, risk, gate, report)

The Rust scanning engine is located in:
- `scanner/`: High-performance filesystem walker and pattern scanner
