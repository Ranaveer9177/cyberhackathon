# Reports Directory — VibeGuard v5.1.0

This directory holds generated security scan reports:
- `scan.json`: Machine-readable scan output (`--format json`)
- `scan.html`: Interactive HTML security verification report (`--format html`)
- `scan.sarif`: OASIS SARIF 2.1.0 output for GitHub Code Scanning (`--format sarif`)

### Transparent Reporting Options
- Standard scan output focuses on blocking findings (Critical, High, Medium).
- Use `--verbose`, `-v`, or `--all` to view full details on low-severity and advisory items.

### Isolation Policy
As of VibeGuard v5.0+, the `reports/` directory is unconditionally skipped by both the Rust scanner and Go fallback engine, ensuring that generated scan reports never trigger recursive or false-positive findings during repository scans.

