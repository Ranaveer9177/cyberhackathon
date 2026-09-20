# Reports Directory

This directory holds generated security scan reports:
- `scan.json`: Machine-readable scan output (`--format json`)
- `scan.html`: Interactive HTML security verification report (`--format html`)
- `scan.sarif`: SARIF 2.1.0 output (`--format sarif`)

Generated reports and version-specific test evidence are maintained in the
external `VibeGuard-test` workspace; this directory is reserved for local
output when running the CLI from the source repository.
