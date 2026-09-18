# VibeGuard — Language & Technology Specification

## 1. Purpose

This document defines the programming languages, frameworks, libraries,
tools, databases, APIs, and software used to develop VibeGuard.

Each technology is assigned to a specific responsibility so that the
project remains modular and maintainable.

---

# 2. Technology Overview

| Area | Technology | Purpose |
|---|---|---|
| Main CLI | Go | User interface and orchestration |
| Security Scanner | Rust | Fast project and source scanning |
| Dependency Vulnerability | OSV API | Vulnerability/advisory lookup |
| AI (Optional) | Ollama | Security explanation and remediation |
| Output | Terminal | Real-time scan results |
| Report | HTML | Human-readable security report |
| Data Exchange | JSON | Go ↔ Rust communication |
| Testing | Go/Rust testing tools | Automated tests |
| Version Control | Git | Source-code management |
| Container Testing | Docker | Test vulnerable projects |
| Development OS | Linux | Development environment |
| Build | Go + Cargo | Compile project |
| Documentation | Markdown | Project documentation |

---

# 3. Go

## Role

Go is the main application and orchestration language.

## Used For

- CLI
- Command handling
- Scanner orchestration
- Calling the Rust scanner
- Dependency processing
- OSV API communication
- Finding aggregation
- Severity calculation
- Security score
- Report generation
- Configuration
- Deployment decision

## Example

    vibeguard scan ./project

The Go application receives this command and controls the entire scanning
process.

## Why Go?

- Fast compilation
- Simple syntax
- Excellent command-line support
- Good concurrency
- Easy HTTP/API communication
- Produces standalone binaries
- Suitable for developer/security tools

## Main Go Structure

    cmd/
    internal/
        scanner/
        dependencies/
        osv/
        report/
        risk/
        config/

---

# 4. Rust

## Role

Rust is the security scanning engine.

## Used For

- Recursive file scanning
- File traversal
- Secret detection
- Pattern matching
- Source-code analysis
- Exact line detection
- File classification
- High-performance scanning

## Example

    project/
    ├── src/
    ├── config/
    ├── .env
    └── Dockerfile

Rust scans the project and returns structured findings.

## Why Rust?

- High performance
- Memory safety
- Excellent control over system resources
- Strong type system
- Suitable for security-sensitive software
- Good ecosystem for parsing and pattern matching

## Main Rust Structure

    scanner/
    ├── src/
    │   ├── main.rs
    │   ├── scanner.rs
    │   ├── secrets.rs
    │   ├── sast.rs
    │   ├── files.rs
    │   └── rules.rs
    └── Cargo.toml

---

# 5. Go ↔ Rust Communication

Go and Rust should communicate using JSON.

Architecture:

    Go CLI
       |
       | Execute
       v
    Rust Scanner
       |
       | JSON
       v
    Go

Example Rust output:

    {
      "id": "VG-001",
      "type": "hardcoded-secret",
      "severity": "critical",
      "file": "src/config.go",
      "line": 18
    }

Go receives and processes this information.

## Why JSON?

- Simple
- Language independent
- Easy to debug
- Easy to extend
- Human readable
- Suitable for future scanner languages

---

# 6. OSV

## Role

OSV is the vulnerability intelligence source.

OSV stands for Open Source Vulnerabilities.

## Used For

- Package vulnerability lookup
- Version matching
- Advisory information
- CVE aliases when available
- Fixed versions
- Affected versions

## Process

    Dependency
       |
       v
    Package + Version
       |
       v
    OSV
       |
       v
    Vulnerability Information
       |
       v
    VibeGuard Finding

Example:

    Package: example-package
    Version: 1.2.0

    Vulnerability:
    CVE-XXXX-XXXXX

    Fixed Version:
    1.4.0

## Important

VibeGuard does not create CVE numbers.

Vulnerability information should come from trusted security databases.

---

# 7. Ollama — Optional AI

## Role

Ollama provides optional local AI functionality.

AI is NOT required for the core VibeGuard scanner.

## Used For

- Explaining findings
- Explaining vulnerability impact
- Suggesting remediation
- Explaining insecure code
- Generating secure-code examples
- Summarizing reports

## Architecture

    VibeGuard
        |
        v
    Security Finding
        |
        v
    Ollama
        |
        v
    Explanation / Recommendation

## Important

The deterministic scanner remains the source of truth.

AI should not be responsible for deciding whether a CVE exists.

---

# 8. Terminal

## Role

The terminal is the primary user interface.

Example:

    $ vibeguard scan ./demo-project

    VIBEGUARD SECURITY SCANNER

    Project: demo-project

    [CRITICAL] VG-001
    Hardcoded API Key
    File: src/config.go
    Line: 18

    [HIGH] VG-002
    Vulnerable Dependency
    Package: example-package

    Security Score: 54/100

    Deployment Status: BLOCKED

---

# 9. HTML

## Role

HTML is used for detailed security reports.

Example:

    reports/
    └── demo-project-report.html

The report can contain:

- Project information
- Scan timestamp
- Security score
- Severity summary
- Findings
- File locations
- CVE/advisory information
- Recommendations
- Deployment status

---

# 10. JSON

## Role

JSON is used for machine-readable output.

Example:

    vibeguard scan ./project --format json

JSON can later be consumed by:

- CI/CD
- Web dashboards
- Other security tools
- Automation scripts

---

# 11. Regular Expressions

## Role

Regex is used for detecting recognizable secret patterns and insecure
code patterns.

Examples:

- API keys
- Tokens
- Password assignments
- Private keys
- Dangerous function patterns

Example:

    API_KEY = "demo_secret"

The scanner can identify the suspicious assignment.

## Important

Regex should not be the only detection technique.

Future versions can combine:

- Regex
- Entropy analysis
- Parsing
- AST analysis
- Context analysis

---

# 12. AST Parsing

## Status

Future enhancement.

## Purpose

AST means Abstract Syntax Tree.

Instead of only searching text patterns, VibeGuard can understand source
code structure.

This can improve detection of:

- SQL injection
- Command injection
- Unsafe function calls
- Authentication problems
- Insecure data flow

Possible language-specific parsers can be added later.

---

# 13. Git

## Role

Git is used for:

- Version control
- Development history
- Branch management
- Collaboration
- Security testing

VibeGuard can also inspect Git repositories.

Possible checks:

- `.env` tracked in Git
- Private keys tracked in Git
- Sensitive files
- Missing `.gitignore`

Future:

- Secret detection in Git history

---

# 14. Docker

## Role

Docker is used for:

- Creating vulnerable demo applications
- Testing VibeGuard
- Reproducing security issues
- Container security testing
- Consistent development environments

Example:

    test-project/
    ├── Dockerfile
    ├── go.mod
    └── src/

VibeGuard analyzes the project before deployment.

---

# 15. Linux

## Role

Linux is the primary development and testing environment.

Used for:

- Development
- Compilation
- Testing
- CLI execution
- Docker
- Git
- Security testing

VibeGuard should eventually support:

- Linux
- Windows
- macOS

---

# 16. Go CLI Technology

The CLI can initially use Go's standard libraries.

Possible commands:

    vibeguard scan
    vibeguard report
    vibeguard version
    vibeguard config

A CLI framework such as Cobra can be added if the command structure
becomes larger.

## Initial Recommendation

Start with:

    Go standard library

Add a CLI framework only if needed.

---

# 17. Rust Libraries

Potential Rust components:

| Library/Technology | Purpose |
|---|---|
| `walkdir` | Recursive directory traversal |
| `regex` | Pattern detection |
| `serde` | Serialization |
| `serde_json` | JSON communication |
| `sha2` | Hashing if required |
| `clap` | Rust CLI if scanner has standalone commands |

Only add libraries that are actually required.

---

# 18. Go Libraries

Potential Go components:

| Library/Technology | Purpose |
|---|---|
| `net/http` | API requests |
| `encoding/json` | JSON processing |
| `os/exec` | Execute Rust scanner |
| `os` | File operations |
| `path/filepath` | File paths |
| `text/template` | Report generation |
| `regexp` | Additional Go-side pattern matching |

External dependencies should be kept minimal.

---

# 19. Dependency Detection

VibeGuard identifies project ecosystems using manifest files.

| File | Ecosystem | Language |
|---|---|---|
| `go.mod` | Go | Go |
| `package.json` | npm | JavaScript/TypeScript |
| `requirements.txt` | PyPI | Python |
| `Cargo.toml` | crates.io | Rust |
| `pom.xml` | Maven | Java |
| `build.gradle` | Gradle | Java/Kotlin |

Initial hackathon support:

    Go
    npm
    Python
    Rust

Future:

    Java
    PHP
    Ruby
    .NET

---

# 20. Security Rule Engine

The security rule engine defines what VibeGuard considers suspicious.

Example:

    Rule ID: VG-SEC-001

    Name:
    Hardcoded API Key

    Severity:
    CRITICAL

    Detection:
    Secret pattern

    Recommendation:
    Move credential to secure configuration.

Rules can be stored in code initially.

Future versions can support external rule files.

---

# 21. Report Technology

The report system should use Go.

Flow:

    Findings
       |
       v
    Go Report Engine
       |
       +---- Terminal
       |
       +---- JSON
       |
       +---- HTML

Future:

       +---- PDF
       +---- SARIF

---

# 22. Testing Technologies

## Go

Use:

    go test

For:

- CLI tests
- OSV client tests
- Risk scoring tests
- Report tests

## Rust

Use:

    cargo test

For:

- Secret detection
- File scanning
- Rule detection
- JSON output

---

# 23. Test Project

A dedicated vulnerable project should be included.

Example:

    test-project/
    ├── .env
    ├── Dockerfile
    ├── package.json
    ├── src/
    │   ├── auth.js
    │   └── database.js
    └── README.md

The project should contain only fake/demo secrets.

This allows repeatable testing.

---

# 24. Development Tools

Recommended:

- VS Code
- Git
- GitHub
- Go
- Rust
- Cargo
- Docker
- Linux terminal
- curl
- jq

Optional:

- Wireshark
- Nmap
- Burp Suite

Security testing tools should be used only where relevant to the
specific VibeGuard test environment.

---

# 25. Complete Technology Flow

    Developer Project
           |
           v
       Go CLI
           |
           v
     Rust Scanner
           |
      +----+----+----+
      |    |    |    |
    Secret SAST Files Config
      |
      v
    Findings
      |
      v
    Go Engine
      |
      +---------> OSV
      |              |
      |              v
      |         CVE/Advisory
      |
      v
    Risk Engine
      |
      v
    Report
      |
      +---- Terminal
      |
      +---- JSON
      |
      +---- HTML
      |
      v
    PASS / BLOCK

Optional:

    Finding
       |
       v
    Ollama
       |
       v
    Explanation / Fix Suggestion

---

# 26. Hackathon Technology Scope

For the 6-hour hackathon, use only:

### Required

    Go
    Rust
    JSON
    OSV
    Git
    Linux
    Terminal
    HTML

### Optional

    Docker
    Ollama

### Future

    Web Dashboard
    CI/CD
    SBOM
    PDF
    SARIF
    Cloud AI
    Automatic Fixing
    Database
    Authentication

---

# 27. Language Responsibility Summary

| Language | Main Responsibility |
|---|---|
| Go | Main application |
| Rust | Security scanning engine |
| JSON | Component communication |
| HTML | Security reports |
| Markdown | Documentation |
| Shell | Build/test automation |

---

# 28. Why Two Programming Languages?

VibeGuard intentionally separates responsibilities.

Go provides:

- Application orchestration
- CLI
- APIs
- Reporting
- Easy deployment

Rust provides:

- High-performance scanning
- Memory safety
- Security-sensitive processing
- Efficient file analysis

This creates a modular architecture where the scanner can evolve
independently from the main application.

---

# 29. Future Architecture

The architecture should allow additional scanners to be added later.

Example:

    VibeGuard
       |
       +---- Rust Scanner
       |
       +---- Go Scanner
       |
       +---- Container Scanner
       |
       +---- Dependency Scanner
       |
       +---- Custom Scanner
       |
       +---- AI Provider

Each scanner produces a common finding format.

---

# 30. Technology Selection Principle

Every technology should have a clear purpose.

Avoid adding a programming language or framework just because it is
popular.

The project should prioritize:

1. Security
2. Reliability
3. Performance
4. Maintainability
5. Simplicity
6. Privacy
7. Extensibility

---

# 31. Final Stack

VibeGuard Hackathon Stack:

    ┌─────────────────────────────┐
    │          VibeGuard          │
    ├─────────────────────────────┤
    │ Go                          │
    │ Main CLI + Orchestration    │
    ├─────────────────────────────┤
    │ Rust                        │
    │ Security Scanner            │
    ├─────────────────────────────┤
    │ OSV                         │
    │ Vulnerability Intelligence  │
    ├─────────────────────────────┤
    │ JSON                        │
    │ Data Exchange               │
    ├─────────────────────────────┤
    │ Terminal + HTML             │
    │ Results & Reports           │
    ├─────────────────────────────┤
    │ Git + Docker                │
    │ Development & Testing       │
    ├─────────────────────────────┤
    │ Ollama (Optional)           │
    │ Local AI Assistance         │
    └─────────────────────────────┘
