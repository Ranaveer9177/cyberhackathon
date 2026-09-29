# VibeGuard — Terms and Conditions of Use

**Effective Date:** September 30, 2026  
**Product Version:** v7.2.0  
**Project:** VibeGuard Autonomous Pre-Push Security Firewall & Deep Static Analyzer  

---

## 1. Acceptance of Terms

By installing, downloading, building, compiling, executing, or integrating **VibeGuard** (including its command-line utilities `vibeguard` and `vibeguard-scanner`, internal packages, scripts, rules, and configuration templates), you acknowledge that you have read, understood, and agree to be bound by these Terms and Conditions ("Terms") and the companion [LICENSE](LICENSE) (Apache License 2.0).

If you do not agree to these Terms, do not install, access, or use the software.

---

## 2. Permitted Use & Commercial Rights

Under the terms of the Apache License 2.0, you are granted permission to:
- **Internal Commercial & Enterprise Deployment:** You may deploy VibeGuard across developer workstations, internal continuous integration (CI) environments, pre-commit/pre-push hooks, and build pipelines without royalty or licensing fees.
- **Modification & Extension:** You may modify, enhance, or customize the scanner engine, AST parsing rules, semantic analyzers, and reporting formats to align with your organization's specific security policies.
- **Redistribution:** You may redistribute original or modified copies of the software in source or binary form, provided all copyright notices, license texts, and attribution notices are preserved as outlined in Section 4 of the Apache License 2.0.

---

## 3. Acceptable Use & Ethical Security Policy

VibeGuard is designed specifically as a **defensive security auditing and vulnerability prevention tool**.

### 3.1 Authorized Scanning Only
You agree that you will only execute VibeGuard against:
1. Source code, repositories, containers, and configuration files that you personally own or have created; or
2. Third-party systems, codebases, and repositories for which you have received express, documented authorization from the legitimate copyright holder or system owner.

### 3.2 Prohibited Exploitative Activities
You strictly agree NOT to:
- Utilize VibeGuard's detection logic, rules, or vulnerability heuristics to intentionally exploit, harm, disrupt, or gain unauthorized access to computer systems, networks, or confidential data.
- Integrate VibeGuard into malware, ransomware, botnets, or offensive penetration tools intended for unauthorized exploitation.
- Circumvent or tamper with security controls of third-party platforms in violation of applicable laws or service agreements.

---

## 4. Privacy, Data Protection & Offline Operation Guarantees

VibeGuard was engineered with an **Offline-First Privacy Architecture**:

1. **Zero Mandatory Network Telemetry:**  
   VibeGuard does NOT collect, harvest, phone-home, or transmit your proprietary source code, credentials, file paths, project names, or scan findings to any external server or analytics service.
2. **Local Intelligence Execution:**  
   When executed in `--offline` mode or during standard local Git pre-push hook execution, all vulnerability assessments, secret detection, and dependency checks query the local offline security database (`.vibeguard/database/security.db`) exclusively on your machine.
3. **Redaction of Sensitive Findings:**  
   All reported secrets, API tokens, and private keys undergo automatic in-memory redaction (retaining only non-identifying prefixes, e.g. `AKIAIOSF********`) before appearing in terminal output, desktop notifications, JSON, or HTML reports.
4. **Third-Party Dependency Services:**  
   If the developer explicitly runs commands with online vulnerability refresh enabled (`vibeguard cache-refresh`), VibeGuard queries the public Google Open Source Vulnerabilities (OSV) API strictly with package names and version strings. No source code or project identifiers are sent.

---

## 5. Security Scanner Accuracy Disclaimer & False Negatives

1. **Static Analysis Limitations:**  
   Static Application Security Testing (SAST), heuristic secret detection, and Software Composition Analysis (SCA) are inherently probabilistic techniques. While VibeGuard strives for 100% precision and recall on supported benchmark patterns, automated scanners cannot prove the complete absence of security flaws.
2. **Complementary Defense:**  
   VibeGuard is designed to serve as a pre-commit/pre-push first line of defense. It does not replace professional manual penetration testing, dynamic application security testing (DAST), threat modeling, or independent third-party forensic code audits.
3. **No Guarantee of Absolute Security:**  
   Neither the authors, contributors, nor maintainers warrant that VibeGuard will detect every possible vulnerability, malicious package, backdoor, or logic defect that may exist in your code.

---

## 6. Disclaimer of Warranty & Limitation of Liability

### 6.1 "AS-IS" Provision
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, VIBEGUARD IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, OR SYSTEM COMPATIBILITY.

### 6.2 Limitation of Damages
IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, CONTRIBUTORS, OR MAINTAINERS BE LIABLE FOR ANY CLAIM, DAMAGES, LOSSES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE, INCLUDING BUT NOT LIMITED TO:
- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES;
- LOSS OF USE, DATA, REVENUE, PROFITS, OR GOODWILL;
- INTERRUPTIONS OF BUSINESS OR PRODUCTION DEPLOYMENTS;
- UNPREVENTED SECURITY BREACHES OR UNIDENTIFIED SYSTEM COMPROMISES.

---

## 7. Responsible Vulnerability Disclosure

If you identify a security defect, bypass, or vulnerability within the VibeGuard scanner engine itself:
1. Please practice responsible disclosure by contacting the maintainers privately rather than opening a public issue tracker report.
2. Provide a minimal reproducible test case, affected version number, and environment details.
3. Allow reasonable time for the maintainers to investigate, remediate, and issue a verified security patch.

---

## 8. Trademarks & Attribution

The name "VibeGuard", associated logos, and branding elements represent the project's identity. You may use the name in factual descriptions, documentation, and academic citations. You may not use the name to falsely imply endorsement, official sponsorship, or affiliation without prior written consent.

---

## 9. Modifications to These Terms

The maintainers reserve the right to modify these Terms as the software evolves. Updated terms will be posted in this repository with a revised effective date. Your continued use of VibeGuard constitutes acceptance of the modified Terms.

---

*For license terms governing source code and compilation, refer to the [Apache License 2.0](LICENSE).*
