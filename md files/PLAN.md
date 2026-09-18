# 1. Project Name

**VibeGuard**

### Full Name

**VibeGuard — Pre-Deployment Security Verification CLI**

---

# 2. Project Objective

Build a command-line security verification tool that scans a software
project before deployment and identifies common security weaknesses.

VibeGuard will analyze the project for:

- Hardcoded secrets
- Sensitive files
- Insecure source-code patterns
- Vulnerable dependencies
- Basic configuration issues
- Docker security issues
- Git security issues

The tool will provide:

- Exact file location
- Line number
- Finding type
- Severity
- Security explanation
- CVE/advisory information where applicable
- Security score
- Deployment decision
- Security report

---

# 3. Hackathon Scope

## Target Platform

For the hackathon prototype:

**Windows only**



4. Technology Stack
Main Application

Go

Used for:

CLI
Orchestration
Finding aggregation
OSV API
Risk scoring
Report generation
Deployment decision
Security Scanner

Rust

Used for:

File traversal
Secret detection
Source-code pattern detection
Exact file/line detection
Security rules
Vulnerability Intelligence

OSV

Used for:

Dependency vulnerability lookup
Advisory information
CVE aliases where available
Affected versions
Fixed versions
Interface

PowerShell 7+

Used as the Windows command-line environment for running the prototype.

Data Exchange

JSON

Used for:

Rust → Go communication
Machine-readable scan results
Report data
Reports

Initial:

Terminal
JSON
HTML
Development
Windows
PowerShell 7+
Git
VS Code
Go
Rust
Cargo
5. Architecture
                    PowerShell 7+
                          |
                          v
                  VibeGuard CLI
                       (Go)
                          |
              +-----------+-----------+
              |                       |
              v                       v
       Rust Security Scanner         OSV
              |                       |
       +------+------+                 |
       |      |      |                 |
    Secrets  SAST  Files               |
       |      |      |                 |
       +------+------+                 |
              |                       |
              +-----------+-----------+
                          |
                          v
                    Finding Engine
                          |
                          v
                     Risk Engine
                          |
             +------------+------------+
             |            |            |
             v            v            v
         Terminal       JSON         HTML
                          |
                          v
                  PASS / BLOCK
6. Repository Structure
VibeGuard/
│
├── FEATURES.md
├── PLAN.md
├── PROCESSES.md
├── LANGUAGE.md
├── CHANGELOG.md
├── README.md
│
├── cmd/
│   └── vibeguard/
│
├── internal/
│   ├── dependencies/
│   ├── osv/
│   ├── risk/
│   ├── report/
│   └── config/
│
├── scanner/
│   ├── src/
│   │   ├── main.rs
│   │   ├── scanner.rs
│   │   ├── files.rs
│   │   ├── secrets.rs
│   │   ├── sast.rs
│   │   └── rules.rs
│   └── Cargo.toml
│
├── tests/
│   ├── secrets/
│   ├── sast/
│   ├── dependencies/
│   └── integration/
│
├── test-project/
│
└── reports/
7. Development Rules
Rule 1

Build the smallest working version first.

Rule 2

Every completed feature must have a test.

Rule 3

Every completed version must be buildable and runnable.

Rule 4

Do not start a new major feature if the previous version is broken.

Rule 5

Use fake credentials only in test projects.

Rule 6

Do not generate fake CVEs.

Rule 7

OSV is the source of truth for dependency vulnerability information.

Rule 8

AI is NOT required for the prototype.

Rule 9

Do not build a web dashboard during the 6-hour MVP.

Rule 10

Do not implement automatic code modification during the hackathon.

8. Version Strategy

Development will be divided into small versions.

v0.1 → Foundation
v0.2 → Secret Detection
v0.3 → Source Security
v0.4 → Dependency Security
v0.5 → Risk & Reporting
v0.6 → Deployment Gate
v0.7 → Docker/Git/Configuration
v1.0 → Stable MVP

The exact implementation priority may be adjusted according to the
remaining hackathon time.

9. VERSION v0.1 — Foundation
Objective

Create the basic VibeGuard CLI and connect the Go application to the
Rust scanner.

Features
Go CLI
scan command
Project path argument
Rust scanner executable
Recursive directory scanning
JSON communication
Basic terminal output
CLI
.\vibeguard.exe scan .\test-project
Go Responsibilities
Receive CLI command
Validate project path
Start Rust scanner
Read JSON output
Display results
Rust Responsibilities
Receive project path
Recursively scan files
Return basic file information
Produce valid JSON
Expected Output
VibeGuard Security Scanner

Project: test-project

Scanning...

Files scanned: 25

Scan completed successfully.
Tests
Test 1

Run scanner against an existing directory.

Expected:

Scan completed successfully.
Test 2

Run scanner against an invalid directory.

Expected:

Error: Project path does not exist.
Test 3

Verify Rust JSON output.

Expected:

Valid JSON.

Build

Go:

go build

Rust:

cargo build --release
Deploy/Test Status
v0.1

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
10. VERSION v0.2 — Secret Detection
Objective

Detect common secrets and credentials inside project files.

Features

Detect:

API keys
Password assignments
Tokens
JWT-like secrets
Private keys
.env files
Credential files
Rust Module
scanner/src/secrets.rs
Detection Methods

Initial:

Regular expressions
Keywords
File-name patterns

Future:

Entropy analysis
Context analysis
Finding Format

Example:

{
  "id": "VG-001",
  "category": "secret",
  "severity": "CRITICAL",
  "title": "Hardcoded Secret Detected",
  "file": "src/config.go",
  "line": 18
}
Terminal Output
[CRITICAL] VG-001
Hardcoded Secret Detected

File: src/config.go
Line: 18
Type: API Key
Secret Protection

Do not display complete secrets.

Example:

Detected:
sk-demo-************
Tests

Test cases:

Fake API key
Fake password
Fake token
.env
Private-key pattern
Normal text
False positive example
Success Criteria
[PASS] API key detection
[PASS] Password detection
[PASS] Token detection
[PASS] Sensitive file detection
[PASS] Secret masking
Deploy

Build the scanner and run it against:

test-project/
Status
v0.2

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
11. VERSION v0.3 — Source Code Security
Objective

Detect common insecure coding patterns.

Initial Security Rules

Implement only practical rules that can be completed during the
hackathon.

Examples:

Dangerous command execution
SQL query concatenation
Dangerous eval
Disabled TLS verification
Weak cryptographic algorithm
Insecure HTTP usage
Hardcoded credentials
Rule Structure

Each rule should contain:

Rule ID
Name
Category
Severity
Detection Pattern
Description
Recommendation
Example
Rule ID: VG-SQL-001

Name:
Possible SQL Injection

Severity:
HIGH
Example Finding
[HIGH] VG-010
Possible SQL Injection

File: src/database.go
Line: 42

Reason:
User-controlled input appears to be directly concatenated
into an SQL query.
Tests

Create vulnerable examples for:

SQL injection pattern
Command execution
Dangerous eval
Weak crypto
Disabled TLS verification

Also test safe code to reduce false positives.

Success Criteria
[PASS] Rule engine
[PASS] File detection
[PASS] Line detection
[PASS] Severity
[PASS] Finding IDs
Status
v0.3

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
12. VERSION v0.4 — Dependency Security
Objective

Detect project dependencies and identify known vulnerabilities.

Supported Ecosystems

For the MVP:

Go
npm
Python
Rust
Dependency Files
go.mod
go.sum

package.json
package-lock.json

requirements.txt

Cargo.toml
Cargo.lock
Process
Project
   |
   v
Detect dependency file
   |
   v
Extract package + version
   |
   v
Query OSV
   |
   v
Receive vulnerability data
   |
   v
Create VibeGuard finding
Finding Information

Include:

Package
Installed version
Vulnerability ID
CVE alias if available
Advisory
Severity
Affected versions
Fixed version
Dependency file
Important

VibeGuard must NOT invent CVE information.

Example:

Package:
example-package

Installed:
1.2.0

Advisory:
OSV-XXXX

CVE:
CVE-XXXX-XXXXX

Fixed:
1.4.0

Only display fields returned by the vulnerability source.

Tests

Test:

Known vulnerable dependency
Safe dependency
Unknown package
Invalid version
OSV unavailable
Multiple dependencies
Failure Handling

If OSV cannot be reached:

Dependency vulnerability lookup unavailable.

Local security checks will continue.

The complete scanner should not crash.

Status
v0.4

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
13. VERSION v0.5 — Risk Scoring & Reporting
Objective

Combine all findings into a clear security report.

Severity Levels
CRITICAL
HIGH
MEDIUM
LOW
INFO
Risk Score

Generate a deterministic security score.

Example:

Security Score: 62/100

The scoring formula must be documented.

Terminal Report

Example:

========================================
       VIBEGUARD SECURITY REPORT
========================================

Project: DemoShop

Critical : 2
High     : 3
Medium   : 4
Low      : 2
Info     : 1

Security Score: 62/100

Secrets        : 2
Source Code    : 4
Dependencies   : 3
Configuration  : 1

========================================

Deployment Status: BLOCKED
========================================
JSON Report

Command:

.\vibeguard.exe scan .\test-project --format json

Output:

reports/scan.json
HTML Report

Command:

.\vibeguard.exe report .\test-project --format html

Output:

reports/scan.html
Tests
Score calculation
Severity counting
JSON generation
HTML generation
Empty findings
Multiple findings
Status
v0.5

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
14. VERSION v0.6 — Deployment Gate
Objective

Use security findings to determine whether deployment should be
allowed or blocked.

Default Policy

Example:

Any CRITICAL finding
        ↓
DEPLOYMENT BLOCKED

Configurable policies can be added later.

Example
Critical: 2
High: 3

Deployment Status: BLOCKED

After fixing:

Critical: 0
High: 0

Deployment Status: PASSED
Exit Codes

Example:

0 = PASS
1 = SECURITY FINDINGS / BLOCK
2 = SCANNER ERROR

This allows future CI/CD systems to use VibeGuard.

Test

Run:

.\vibeguard.exe scan .\test-project

Verify that:

Critical finding → exit code 1

Then remove the critical finding.

Run again:

No blocking findings → exit code 0
Status
v0.6

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
15. VERSION v0.7 — Additional Security Checks
Objective

Add additional security checks if sufficient hackathon time remains.

Docker Security

Check:

Root user
Privileged mode
Hardcoded secrets
Unsafe base image
Exposed ports
Unsafe configuration
Git Security

Check:

.env
Private keys
Credential files
Sensitive files
.gitignore
Configuration Security

Check:

Debug mode
Insecure HTTP
Disabled TLS
Unsafe CORS
Default credentials
Priority

These features are optional for the 6-hour MVP.

Do not delay the working v0.6 system to implement them.

Status
v0.7

Implementation: ⬜
Build: ⬜
Test: ⬜
Deploy: ⬜
16. VERSION v1.0 — Stable MVP
Objective

Create the final hackathon-ready VibeGuard prototype.

Required Features
[ ] Cross-project scanning
[ ] Secret detection
[ ] Source-code security rules
[ ] Dependency detection
[ ] OSV vulnerability lookup
[ ] Finding IDs
[ ] Severity
[ ] Exact file locations
[ ] Line numbers
[ ] Security score
[ ] Terminal report
[ ] JSON report
[ ] HTML report
[ ] PASS/BLOCK decision
Final CLI

Main command:

.\vibeguard.exe scan .\test-project

Report:

.\vibeguard.exe report .\test-project --format html

Version:

.\vibeguard.exe version
17. Test Project

Create a deliberately vulnerable project for demonstration.

test-project/
│
├── .env
├── Dockerfile
├── go.mod
├── package.json
│
├── src/
│   ├── config.go
│   ├── database.go
│   └── auth.js
│
└── README.md
Test Vulnerabilities

The test project should contain controlled fake examples:

1. Fake API key
2. Fake password
3. Sensitive .env file
4. Vulnerable dependency
5. SQL injection pattern
6. Dangerous command execution
7. Weak crypto
8. Docker root configuration

Only fake credentials should be used.

18. Integration Testing

Run the complete system:

.\vibeguard.exe scan .\test-project

Verify:

Go starts successfully
        ↓
Rust scanner starts
        ↓
Files are scanned
        ↓
Findings are returned
        ↓
Dependencies are checked
        ↓
OSV results are processed
        ↓
Severity is calculated
        ↓
Security score is generated
        ↓
Report is created
        ↓
PASS/BLOCK is returned
19. Final Demonstration
Demo Part 1 — Vulnerable Project

Run:

.\vibeguard.exe scan .\test-project

Show:

CRITICAL
HIGH
MEDIUM
LOW

Security Score

Deployment Status: BLOCKED
Demo Part 2 — Finding Details

Show:

VG-001

Hardcoded Secret

File:
src/config.go

Line:
18

Severity:
CRITICAL

Recommendation:
Move the credential to secure configuration.
Demo Part 3 — Dependency Vulnerability

Show:

VG-005

Vulnerable Dependency

Package:
example-package

Version:
1.2.0

CVE:
CVE-XXXX-XXXXX

Fixed Version:
1.4.0
Demo Part 4 — Fix

Fix the controlled vulnerabilities in the test project.

Run:

.\vibeguard.exe scan .\test-project

Show the reduced findings.

Demo Part 5 — Deployment Pass

Show:

Critical: 0
Blocking Findings: 0

Deployment Status: PASSED

This demonstrates the complete security verification cycle.

20. Six-Hour Hackathon Schedule
Hour 1 — Foundation

Tasks:

Create repository
Create folder structure
Initialize Go
Initialize Rust
Implement CLI
Implement Go → Rust communication
Test basic scanning

Target:

v0.1
Hour 2 — Secret Scanner

Tasks:

File traversal
Secret rules
API key detection
Password detection
Token detection
Sensitive file detection
Finding IDs
Severity

Target:

v0.2
Hour 3 — Source Security

Tasks:

Rule engine
SQL injection pattern
Command execution
Weak crypto
TLS verification
Exact line detection
Test cases

Target:

v0.3
Hour 4 — Dependency Security

Tasks:

Detect dependency files
Parse packages
Query OSV
Process vulnerability results
Display CVE/advisory
Fixed version
Error handling

Target:

v0.4
Hour 5 — Reports & Deployment Gate

Tasks:

Risk score
Terminal report
JSON report
HTML report
PASS/BLOCK
Exit codes

Target:

v0.5
v0.6
Hour 6 — Testing & Demo

Tasks:

Complete integration testing
Fix bugs
Prepare vulnerable test project
Run final scan
Run clean scan
Generate final report
Prepare screenshots
Prepare presentation
Prepare project documentation

Target:

v1.0
21. Priority System

If time becomes limited:

P0 — MUST HAVE
Go CLI
Rust scanner
Directory scanning
Secret detection
Basic source rules
Dependency detection
OSV lookup
Terminal output
P1 — SHOULD HAVE
Risk score
JSON report
HTML report
PASS/BLOCK
Exit codes
P2 — NICE TO HAVE
Docker scanning
Git scanning
Configuration scanning
Ignore file
P3 — FUTURE
AI
Automatic fixing
Dashboard
CI/CD integration
SBOM
Cloud platform
Historical scans
22. What NOT To Build During The Hackathon

Do not spend hackathon time on:

❌ Web dashboard
❌ User authentication
❌ Database
❌ Cloud deployment
❌ SaaS platform
❌ Automatic code fixing
❌ Complex AI system
❌ Full SAST engine
❌ Mobile application
❌ Linux/macOS builds
❌ Team management
❌ Billing

These belong in the future roadmap.

23. Windows Prototype Environment
Required
Windows
PowerShell 7+
Go
Rust
Cargo
Git
VS Code
Internet connection for OSV lookup
24. Build Process

Rust:

cargo build --release

Go:

go build

Final prototype:

vibeguard.exe
vibeguard-scanner.exe
25. Final Windows Prototype
Windows
   |
   v
PowerShell 7+
   |
   v
vibeguard.exe
   |
   v
vibeguard-scanner.exe
   |
   +---- Secret Scanner
   |
   +---- Source Scanner
   |
   +---- Dependency Scanner
   |
   +---- OSV
   |
   v
Finding Engine
   |
   v
Risk Score
   |
   v
Security Report
   |
   v
PASS / BLOCK
26. Completion Checklist
Foundation
 Repository created
 Go project initialized
 Rust project initialized
 CLI working
 Go → Rust communication working
Security
 Secret detection working
 Source security rules working
 Dependency detection working
 OSV lookup working
 Findings have IDs
 Findings have severity
 File and line information working
Reporting
 Terminal report
 JSON report
 HTML report
 Security score
 PASS/BLOCK
Testing
 Unit tests
 Scanner tests
 OSV tests
 Integration test
 Vulnerable test project
 Clean project test
Documentation
 FEATURES.md
 PLAN.md
 PROCESSES.md
 LANGUAGE.md
 CHANGELOG.md
 README.md
Presentation
 Problem statement
 Proposed solution
 Architecture
 Technologies
 Live demo
 Screenshots
 Results
 Future scope
27. Final Success Criteria

The prototype is considered successful when a developer can execute:

.\vibeguard.exe scan .\test-project

and VibeGuard can:

1. Scan the project
2. Detect security issues
3. Identify exact locations
4. Assign severity
5. Check dependencies
6. Retrieve trusted vulnerability information
7. Generate a security score
8. Generate a report
9. Decide PASS/BLOCK
10. Complete the process from one CLI command
28. Final Product Definition

VibeGuard is a Windows-based prototype of a cross-platform security
verification CLI.

The prototype uses:

PowerShell 7+ for the command-line environment
Go for the main application and orchestration
Rust for security scanning
OSV for dependency vulnerability intelligence
JSON for component communication
HTML/JSON/terminal for reporting

The core purpose is to provide developers with an independent security
verification step before software deployment.

29. Future Expansion

After the hackathon, VibeGuard can be expanded to:

v1.1 — Linux support
v1.2 — macOS support
v1.3 — Docker scanning
v1.4 — Git security
v1.5 — CI/CD integration
v1.6 — SBOM
v1.7 — Web dashboard
v1.8 — AI security assistant
v1.9 — AI remediation suggestions
v2.0 — Full developer security platform
30. Development Principle

Build → Test → Fix → Build → Deploy

Every version should follow:

PLAN
  ↓
IMPLEMENT
  ↓
TEST
  ↓
FIX
  ↓
BUILD
  ↓
DEPLOY
  ↓
DOCUMENT
  ↓
NEXT VERSION
31. Current Project Status
Project:
VibeGuard

Platform:
Windows

CLI Environment:
PowerShell 7+

Core Language:
Go

Scanner Language:
Rust

Vulnerability Source:
OSV

Current Version:
v0.0 — Planning

Next Version:
v0.1 — Foundation

Hackathon Duration:
6 Hours

Status:
PLANNING