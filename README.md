# AminScan

**AminScan** is a lightweight DevSecOps scanner that detects:
- leaked secrets in source code (regex + optional entropy heuristic)
- basic web misconfigurations for a deployed URL (headers, HTTPS enforcement, risky CORS, banner disclosure)

It’s designed to be **low-noise**, **CI-friendly**, and **safe** (never prints full secrets).

---

## Features

### Secrets scanning (repo)
- Detects common token/key patterns
- Optional entropy heuristic for unknown tokens (`SEC-ENTROPY-TOKEN`)
- Findings include file + line + masked evidence + fix suggestion

### Web scanning (URL)
- HTTPS enforcement check
- Missing baseline security headers
- Risky CORS check (`Access-Control-Allow-Origin: *` + credentials)
- Basic fingerprinting headers (Server, X-Powered-By)
- Safe probing for common sensitive paths (non-destructive)

### Reporting
- Markdown report: `aminscan-report.md`
- JSON report: `aminscan-report.json`
- Exit code for CI gates (fails builds based on severity threshold)

---

## Install (local dev)

```bash
pip install -e .
