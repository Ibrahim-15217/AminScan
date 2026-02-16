from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    recommendation: str


RULES: list[SecretRule] = [
    SecretRule(
        id="SEC-AWS-ACCESS-KEY",
        title="Possible AWS Access Key ID",
        severity="high",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        recommendation="Rotate/revoke the key and remove it from git history (use git filter-repo).",
    ),
    SecretRule(
        id="SEC-GITHUB-TOKEN",
        title="Possible GitHub token",
        severity="high",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        recommendation="Revoke the token in GitHub settings and rotate credentials.",
    ),
    SecretRule(
        id="SEC-GOOGLE-API-KEY",
        title="Possible Google API key",
        severity="high",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        recommendation="Restrict and rotate the key in your cloud console; remove it from git history.",
    ),
    SecretRule(
        id="SEC-SLACK-TOKEN",
        title="Possible Slack token",
        severity="high",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        recommendation="Revoke the token in Slack, rotate secrets, and purge from git history.",
    ),
    SecretRule(
        id="SEC-JWT",
        title="Possible JWT token",
        severity="medium",
        pattern=re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        recommendation="Treat as sensitive: invalidate sessions/rotate signing keys if exposed.",
    ),
    SecretRule(
        id="SEC-PRIVATE-KEY",
        title="Private key material detected",
        severity="critical",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----"),
        recommendation="Remove the key immediately, rotate affected credentials, and purge from git history.",
    ),
]
