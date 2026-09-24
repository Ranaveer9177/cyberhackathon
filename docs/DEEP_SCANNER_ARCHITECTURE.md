# VibeGuard Deep Offline Scanner Architecture Specification

> **Version:** 7.0.0 Architecture Blueprint  
> **Status:** Active Implementation  
> **Focus:** Offline-First Semantic Project Modeling, Cross-File Inter-procedural Data-Flow & Vulnerability-Specific Taint Analysis

---

## 1. Overview & Layered Architecture

VibeGuard evolves from a fast pre-push lexical gate into a **two-tier hybrid engine**:
1. **Tier 1 (Fast-Pass Lexical & Heuristic Filter)**: Multi-threaded directory traversal, regex secret entropy analysis, Docker/Compose syntax checks, and rapid file filtering.
2. **Tier 2 (Deep Offline Semantic & Taint Engine)**: AST extraction, project-wide symbol resolution, call graph construction, framework modeling, and vulnerability-specific inter-procedural data-flow tracking.

```text
+-----------------------------------------------------------------------------------+
|                               PROJECT DIRECTORY                                   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        TIER 1: FAST FIRST-PASS LEXICAL LAYER                      |
|                                                                                   |
|  - File Discovery & Ignore Filters (.gitignore, .vibeguardignore)                 |
|  - Language & Config Classification (.py, .js, .go, .java, .dockerfile, .yaml)   |
|  - Entropy-based & Context-Aware Secret Detection                                 |
|  - Docker & Docker Compose Static Infrastructure Analysis                         |
|  - Local Dependency Manifest Parsing (requirements.txt, package.json, go.mod)     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v (Candidate Files & Functions)
+-----------------------------------------------------------------------------------+
|                      TIER 2: DEEP SEMANTIC & DATA-FLOW LAYER                      |
|                                                                                   |
|  +------------------------+  +--------------------------+  +-------------------+  |
|  |     AST Extractor      |  |    Project Symbol Table  |  |    Call Graph     |  |
|  | (Functions, Calls, Var)|  | (Modules, Imports, Decls)|  | (Caller -> Callee)|  |
|  +------------------------+  +--------------------------+  +-------------------+  |
|                                          |                                        |
|                                          v                                        |
|  +-----------------------------------------------------------------------------+  |
|  |                     Vulnerability-Specific Taint Engine                     |  |
|  |   - SQL Taint           - Command Taint       - SSRF Taint                  |  |
|  |   - Path Traversal      - XSS Taint           - Deserialization Taint       |  |
|  +---------------------------------------+-------------------------------------+  |
|                                          |                                        |
|                                          v                                        |
|  +-----------------------------------------------------------------------------+  |
|  |                       Sink-Specific Sanitizer Modeling                      |  |
|  |   - Numeric Casts (SQL)                       - Shell Escaping (shlex.quote)|  |
|  |   - URL / Hostname Validators (SSRF)          - HTML Entity Escapers (XSS)  |  |
|  +---------------------------------------+-------------------------------------+  |
|                                          |                                        |
|                                          v                                        |
|  +-----------------------------------------------------------------------------+  |
|  |               Framework-Aware Source & Route Analysis                       |  |
|  |   Flask | Django | FastAPI | Express | NestJS | Spring Boot                 |  |
|  +---------------------------------------+-------------------------------------+  |
|                                          |                                        |
|                                          v                                        |
|  +-----------------------------------------------------------------------------+  |
|  |                     Finding Verification & Confidence Engine                |  |
|  |   - Constant Propagation Check                - Reachability & Path Check   |  |
|  |   - Tiering: Confirmed Finding vs Potential Issue vs Informational          |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           REPORTING & SECURITY GATE                               |
|   Terminal Traces | JSON Data-Flow Provenance | SARIF 2.1.0 | Exit Gate Decision  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Components

### 2.1 Project-Wide Semantic Model (`scanner/src/semantic/`)
- **`ProjectModel`**: Aggregates all files, modules, function declarations, type annotations, and symbol cross-references.
- **`SymbolTable`**: 
  - Resolves `module -> symbol`
  - Resolves `import -> module`
  - Resolves `call -> function definition` across different files (`app.py` calling `database.py:execute_query`).
- **`CallGraph`**: Maintains a directed graph of function invocations across files to enable inter-procedural propagation (`routes.py` $\rightarrow$ `service.py` $\rightarrow$ `database.py`).
- **`TypeKind`**: Basic type inference (String, Integer, Float, Boolean, List, Map, Object, Bytes, Unknown) to detect safe transformations (e.g. numeric ID conversions).

### 2.2 Vulnerability-Specific Taint Engine (`scanner/src/taint/`)
Untrusted input is not treated as a single monolithic category. Flows are tracked by vulnerability class:
- **`SQL Taint`**: Sources reach SQL query formatters / execution sinks without parameterization or numeric cast.
- **`Command Taint`**: Sources reach process execution (`os.system`, `subprocess`, `exec`) without shell argument quoting or when `shell=True` is supplied.
- **`Path Taint`**: Sources reach filesystem operations (`open`, `readFile`) without path canonicalization / sandbox containment.
- **`SSRF Taint`**: Sources reach HTTP request dispatchers (`requests.get`, `fetch`, `axios`) without URL allowlist verification.
- **`XSS Taint`**: Sources reach template or HTML response rendering without contextual encoding.
- **`Deserialization Taint`**: Sources reach dynamic object deserializers (`pickle.loads`, `yaml.unsafe_load`).

### 2.3 Framework-Aware Modeling (`scanner/src/frameworks/`)
Recognizes framework-native HTTP entrypoints and sources:
- **Flask**: `request.args`, `request.form`, `request.values`, `request.json`, `request.headers`, `request.cookies`.
- **FastAPI / Pydantic**: Parameter annotations, `Query(...)`, `Body(...)`, `Header(...)`.
- **Django**: `request.GET`, `request.POST`, `request.COOKIES`.
- **Express / Node.js**: `req.query`, `req.body`, `req.params`, `req.headers`.
- **Spring Boot**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`.

### 2.4 Sink-Specific Sanitizer Modeling
A sanitizer only protects specific sinks:
- `int(x)` / `float(x)`: Sanitizes **SQL injection** numeric parameters, but does NOT sanitize XSS or Command injection.
- `shlex.quote(x)`: Sanitizes **Command injection** in shell contexts, but does NOT sanitize SQL or Path Traversal.
- Non-shell command list (`["command", arg]`): Sanitizes **Command injection** by avoiding shell interpretation.
- `os.path.basename(x)`: Sanitizes directory traversal, but does NOT sanitize Command injection.
- `html.escape(x)`: Sanitizes **XSS**, but does NOT sanitize SQL injection.

### 2.5 Finding Verification & Evidence Tiering (`scanner/src/analysis/`)
Findings are classified by evidence completeness to minimize false alarms:
1. **`Confirmed Finding` (High Confidence)**:
   - Verified untrusted Source $\rightarrow$ verified Data-Flow Trace $\rightarrow$ verified dangerous Sink $\rightarrow$ absence of effective sanitizer $\rightarrow$ non-constant value.
2. **`Potential Issue` (Medium Confidence)**:
   - Pattern-matched dangerous sink or partial flow where the origin of the variable could not be definitively traced to an untrusted source or constant.
3. **`Informational / Advisory` (Low Confidence)**:
   - Hardcoded values, test credentials in docs, or benign configurations that merit security awareness without blocking the deployment gate.

---

## 3. Directory Layout in `scanner/src/`

```text
scanner/src/
├── main.rs                   # Entry point and orchestrator
├── types.rs                  # Core data types (Finding, Severity, Category, etc.)
├── rules.rs                  # Rule definitions and CWE mappings
├── scanner.rs                # Multi-threaded file walker & classifier
├── secrets.rs                # High-entropy & regex secret analyzer
├── docker.rs                 # Dockerfile & Docker Compose validator
├── config.rs                 # Repository & app config scanner
├── git.rs                    # Git security & exclusion scanner
├── sast.rs                   # First-pass lexical taint & pattern matching
├── semantic/                 # Project-wide semantic modeling
│   ├── mod.rs                # ProjectModel, SymbolTable, CallGraph
│   ├── symbol.rs             # Cross-file symbol resolution
│   └── types.rs              # Semantic function & type structures
├── taint/                    # Vulnerability-specific taint engine
│   ├── mod.rs                # TaintKind, TaintStep, TaintFlow
│   └── sanitizer.rs          # Sink-specific sanitizer rules
├── frameworks/               # Framework entrypoint models
│   └── mod.rs                # Flask, FastAPI, Django, Express models
└── analysis/                 # Verification & confidence evaluation
    ├── mod.rs                # Finding verification engine
    └── constant.rs           # Constant propagation and literal folding
```
