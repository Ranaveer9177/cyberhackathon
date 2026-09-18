# VibeGuard — PLAN.md

# Development Plan

---

## Phase 1 — Project Foundation

### Step 1
Create the project structure.

### Step 2
Initialize the core application.

### Step 3
Initialize the security scanning engine.

### Step 4
Create communication between the core application and scanning engine.

### Step 5
Create the basic project scanning workflow.

### Step 6
Build the first working version.

### Test
Test the basic scanning workflow.

### Deploy
Deploy the first working version.

### Version
v0.1

---

## Phase 2 — Project & File Scanner

### Step 1
Create recursive project scanning.

### Step 2
Detect files and directories.

### Step 3
Identify project types.

### Step 4
Identify programming languages.

### Step 5
Ignore unnecessary files and directories.

### Step 6
Return scanned file information.

### Test
Test scanning on different project structures.

### Deploy
Integrate the file scanner into the main application.

### Version
v0.2

---

## Phase 3 — Secret Detection

### Step 1
Create the secret detection system.

### Step 2
Add API key detection.

### Step 3
Add password detection.

### Step 4
Add token detection.

### Step 5
Add private key detection.

### Step 6
Add sensitive file detection.

### Step 7
Add secret masking.

### Step 8
Add finding identification.

### Test
Create test projects containing fake secrets.

### Test
Verify detected secrets.

### Test
Verify false-positive handling.

### Deploy
Integrate secret detection into the main scanner.

### Version
v0.3

---

## Phase 4 — Source Code Security

### Step 1
Create the security rule engine.

### Step 2
Add SQL injection detection.

### Step 3
Add command injection detection.

### Step 4
Add dangerous function detection.

### Step 5
Add weak cryptography detection.

### Step 6
Add insecure TLS configuration detection.

### Step 7
Add insecure HTTP detection.

### Step 8
Add exact file and line detection.

### Step 9
Add severity classification.

### Test
Create vulnerable source-code examples.

### Test
Create safe source-code examples.

### Test
Verify findings and locations.

### Deploy
Integrate source-code security into the scanner.

### Version
v0.4

---

## Phase 5 — Dependency Security

### Step 1
Detect dependency files.

### Step 2
Extract package names.

### Step 3
Extract package versions.

### Step 4
Identify the dependency ecosystem.

### Step 5
Connect to a vulnerability intelligence source.

### Step 6
Check dependency versions.

### Step 7
Identify known vulnerabilities.

### Step 8
Retrieve advisory information.

### Step 9
Retrieve CVE information when available.

### Step 10
Retrieve affected versions.

### Step 11
Retrieve fixed versions.

### Test
Test vulnerable dependencies.

### Test
Test safe dependencies.

### Test
Test unknown dependencies.

### Test
Test vulnerability lookup failures.

### Deploy
Integrate dependency security into the scanner.

### Version
v0.5

---

## Phase 6 — Security Finding Engine

### Step 1
Combine results from all scanners.

### Step 2
Create unique finding IDs.

### Step 3
Assign categories.

### Step 4
Assign severity.

### Step 5
Add confidence information.

### Step 6
Add file and line information.

### Step 7
Group related findings.

### Step 8
Count findings by severity.

### Step 9
Create the security scoring system.

### Test
Test multiple findings from different scanners.

### Test
Verify finding IDs.

### Test
Verify severity classification.

### Test
Verify security score calculation.

### Deploy
Integrate the finding engine.

### Version
v0.6

---

## Phase 7 — Security Report

### Step 1
Create the terminal security summary.

### Step 2
Display findings by severity.

### Step 3
Display finding details.

### Step 4
Display file and line locations.

### Step 5
Display dependency vulnerability information.

### Step 6
Display security score.

### Step 7
Create machine-readable output.

### Step 8
Create a detailed report.

### Step 9
Add report generation.

### Test
Generate reports from vulnerable projects.

### Test
Generate reports from clean projects.

### Test
Verify report information.

### Deploy
Integrate reporting into VibeGuard.

### Version
v0.7

---

## Phase 8 — Security Decision & Deployment Gate

### Step 1
Define blocking conditions.

### Step 2
Create deployment status.

### Step 3
Implement PASS status.

### Step 4
Implement BLOCK status.

### Step 5
Create configurable security thresholds.

### Step 6
Create appropriate process exit codes.

### Test
Test projects containing critical findings.

### Test
Test projects without blocking findings.

### Test
Verify exit codes.

### Deploy
Integrate the deployment gate.

### Version
v0.8

---

## Phase 9 — Configuration, Git & Container Security

### Step 1
Add configuration security checks.

### Step 2
Add Git security checks.

### Step 3
Add sensitive Git file detection.

### Step 4
Add Docker security checks.

### Step 5
Add container configuration checks.

### Step 6
Integrate the additional findings.

### Test
Create vulnerable configuration examples.

### Test
Create vulnerable Git examples.

### Test
Create vulnerable container examples.

### Deploy
Integrate the additional security modules.

### Version
v0.9

---

# Phase 10 — Multi-CLI Support

### Step 1
Make the core CLI independent of a specific shell.

### Step 2
Define a consistent command structure.

### Step 3
Test the same commands through different command-line environments.

### Step 4
Test command arguments.

### Step 5
Test command output.

### Step 6
Test error handling.

### Step 7
Test installation and execution.

### Step 8
Document the supported CLI environments.

### Test
Run the same VibeGuard commands through multiple CLI environments.

### Test
Verify that the results remain consistent.

### Deploy
Release the multi-CLI version.

### Version
v1.0

---

# Phase 11 — AI Integration

### Objective

Add AI as an optional intelligence layer without making VibeGuard
dependent on a specific AI provider.

### Step 1
Create an AI integration interface.

### Step 2
Define a standard input format for security findings.

### Step 3
Send selected findings to the configured AI provider.

### Step 4
Receive AI explanations.

### Step 5
Generate remediation suggestions.

### Step 6
Allow developers to configure their preferred AI provider.

### Step 7
Support developer-provided AI credentials or connection settings.

### Step 8
Keep the core security scanner functional without AI.

### Step 9
Prevent AI from being the source of truth for vulnerability detection.

### Step 10
Allow developers to choose their own AI environment.

### AI Design

```text
VibeGuard
    |
    v
Security Finding
    |
    v
AI Interface
    |
    +---- Developer's Local AI
    |
    +---- Developer's Cloud AI
    |
    +---- Developer's Preferred AI Provider