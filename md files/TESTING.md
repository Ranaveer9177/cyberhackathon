# VibeGuard — Testing

# 1. Testing Objective

Testing verifies that VibeGuard correctly detects security issues,
handles valid and invalid input, produces accurate results, and does
not fail when external services are unavailable.

---

# 2. Testing Levels

## Unit Testing

Test individual functions and modules.

## Integration Testing

Test communication between components.

## Scanner Testing

Test security detection rules.

## Dependency Testing

Test vulnerability lookup.

## Report Testing

Test generated reports.

## End-to-End Testing

Test the complete VibeGuard workflow.

---

# 3. Test Case Format

Each test should contain:

- Test ID
- Feature
- Input
- Expected result
- Actual result
- Status

---

# 4. Secret Detection Tests

## TC-001

Feature:
API key detection

Input:
Controlled fake API key

Expected:
Secret detected

Status:
PASS / FAIL

---

## TC-002

Feature:
Password detection

Expected:
Password detected

Status:
PASS / FAIL

---

## TC-003

Feature:
False positive

Input:
Normal source code

Expected:
No secret finding

Status:
PASS / FAIL

---

# 5. Source Security Tests

## TC-010

Feature:
SQL injection detection

Expected:
Security finding generated

Status:
PASS / FAIL

---

## TC-011

Feature:
Command execution

Expected:
Security finding generated

Status:
PASS / FAIL

---

# 6. Dependency Tests

## TC-020

Feature:
Vulnerable dependency

Expected:
Vulnerability identified

Status:
PASS / FAIL

---

## TC-021

Feature:
Safe dependency

Expected:
No vulnerability reported

Status:
PASS / FAIL

---

# 7. Report Tests

## TC-030

Feature:
Terminal report

Expected:
Correct finding summary

Status:
PASS / FAIL

---

## TC-031

Feature:
JSON report

Expected:
Valid JSON

Status:
PASS / FAIL

---

## TC-032

Feature:
HTML report

Expected:
Valid report generated

Status:
PASS / FAIL

---

# 8. Deployment Gate Tests

## TC-040

Critical finding present.

Expected:

BLOCK

Status:
PASS / FAIL

---

## TC-041

No blocking findings.

Expected:

PASS

Status:
PASS / FAIL

---

# 9. End-to-End Test

Input:

Controlled vulnerable project.

Expected workflow:

```text
Scan
 ↓
Detect
 ↓
Analyze
 ↓
Correlate
 ↓
Score
 ↓
Report
 ↓
PASS/BLOCK