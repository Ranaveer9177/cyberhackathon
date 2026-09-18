# DemoShop — Deliberately Vulnerable Test Project

> ⚠️ **WARNING**: This project contains intentionally vulnerable code for security testing purposes only.
> All credentials are **FAKE** and should never be used in any real environment.

## Purpose

This project is used by VibeGuard to demonstrate security scanning capabilities.
It contains controlled examples of common security vulnerabilities:

- Hardcoded API keys and passwords
- SQL injection patterns
- Command injection patterns  
- Dangerous eval() usage
- Weak cryptographic algorithms (MD5)
- Disabled TLS verification
- Insecure HTTP endpoints
- Vulnerable dependencies
- Docker security misconfigurations
- Exposed .env file

## Files

| File | Vulnerabilities |
|------|----------------|
| `.env` | Exposed database credentials, API keys, JWT secret |
| `src/config.go` | Hardcoded secrets, disabled TLS, insecure HTTP |
| `src/database.go` | SQL injection, command injection, weak crypto (MD5) |
| `src/auth.js` | eval(), command injection, hardcoded JWT, insecure HTTP |
| `Dockerfile` | Root user, secrets in ENV, latest tag, no healthcheck |
| `go.mod` | Potentially vulnerable Go dependencies |
| `package.json` | Potentially vulnerable npm dependencies |
| `requirements.txt` | Potentially vulnerable Python dependencies |

## Usage

Scan with VibeGuard:
```powershell
.\vibeguard.exe scan .\test-project
```
