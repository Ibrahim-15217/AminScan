from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin

import requests


SEC_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

# Simple non-destructive probes (GET/HEAD)
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/db.sql",
    "/config",
    "/admin",
]


def scan_web(url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    sess = requests.Session()
    sess.headers.update({"User-Agent": "AminScan/0.0.4"})

    # 1) Fetch the URL (follow redirects)
    try:
        r = sess.get(url, allow_redirects=True, timeout=timeout)
    except Exception:
        return [{
            "rule_id": "WEB-UNREACHABLE",
            "title": "Web scan failed (URL unreachable)",
            "severity": "medium",
            "confidence": "medium",
            "file": None,
            "line": None,
            "evidence_masked": url,
            "recommendation": "Ensure the URL is reachable from your network/CI and try again.",
        }]

    final_url = r.url
    final_lower = final_url.lower()

    # 2) HTTPS enforcement
    if final_lower.startswith("http://"):
        findings.append({
            "rule_id": "WEB-HTTPS-NOT-ENFORCED",
            "title": "HTTPS not enforced (final URL is HTTP)",
            "severity": "high",
            "confidence": "high",
            "file": None,
            "line": None,
            "evidence_masked": final_url,
            "recommendation": "Force HTTPS redirects and enable HSTS (Strict-Transport-Security).",
        })

    # Normalize headers
    headers = {k.lower(): v for k, v in r.headers.items()}

    # 3) Missing security headers (baseline)
    for h in SEC_HEADERS:
        if h not in headers:
            findings.append({
                "rule_id": f"WEB-MISSING-{h.upper()}",
                "title": f"Missing security header: {h}",
                "severity": "medium",
                "confidence": "high",
                "file": None,
                "line": None,
                "evidence_masked": h,
                "recommendation": f"Add `{h}` with a secure value appropriate for your app.",
            })

    # 4) Risky CORS (very basic check)
    aco = headers.get("access-control-allow-origin")
    acc = headers.get("access-control-allow-credentials")
    if aco == "*" and (acc or "").lower() == "true":
        findings.append({
            "rule_id": "WEB-CORS-WILDCARD-CREDS",
            "title": "Risky CORS: wildcard origin with credentials enabled",
            "severity": "high",
            "confidence": "high",
            "file": None,
            "line": None,
            "evidence_masked": "Access-Control-Allow-Origin: * + Allow-Credentials: true",
            "recommendation": "Do not use `*` when credentials are allowed. Set explicit allowed origins.",
        })

    # 5) Banner disclosure (low severity)
    if "server" in headers:
        findings.append({
            "rule_id": "WEB-BANNER-SERVER",
            "title": "Server header disclosed (fingerprinting)",
            "severity": "low",
            "confidence": "medium",
            "file": None,
            "line": None,
            "evidence_masked": headers.get("server", "")[:40],
            "recommendation": "Consider minimizing/removing server version disclosure.",
        })
    if "x-powered-by" in headers:
        findings.append({
            "rule_id": "WEB-BANNER-XPOWEREDBY",
            "title": "X-Powered-By header disclosed (fingerprinting)",
            "severity": "low",
            "confidence": "medium",
            "file": None,
            "line": None,
            "evidence_masked": headers.get("x-powered-by", "")[:40],
            "recommendation": "Disable X-Powered-By header to reduce fingerprinting.",
        })

    # 6) Safe probing for common sensitive paths
    base = final_url if final_url.endswith("/") else final_url + "/"
    for path in SENSITIVE_PATHS:
        target = urljoin(base, path.lstrip("/"))
        try:
            pr = sess.get(target, allow_redirects=True, timeout=timeout)
            if pr.status_code in (200, 206):
                findings.append({
                    "rule_id": "WEB-SENSITIVE-PATH",
                    "title": f"Sensitive path accessible: {path}",
                    "severity": "high",
                    "confidence": "medium",
                    "file": None,
                    "line": None,
                    "evidence_masked": path,
                    "recommendation": "Remove/lock down the resource and verify server configuration.",
                })
        except Exception:
            continue

    return findings
