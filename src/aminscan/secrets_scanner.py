from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from .entropy import TOKEN_RE, looks_like_high_entropy_token
from .file_utils import iter_text_files, load_ignore_patterns
from .secrets_rules import RULES


def scan_secrets(base: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    ignore = load_ignore_patterns(base)
    files = list(iter_text_files(base, ignore))

    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # .env presence warning
        if fp.name == ".env":
            findings.append({
                "rule_id": "SEC-DOTENV",
                "title": ".env file detected (may contain secrets)",
                "severity": "medium",
                "confidence": "high",
                "file": str(fp),
                "line": 1,
                "evidence_masked": ".env",
                "recommendation": "Remove .env from repo and add it to .gitignore. Rotate any exposed values.",
            })

        for line_no, line in enumerate(text.splitlines(), start=1):
            # 1) High-confidence regex rules
            for rule in RULES:
                m = rule.pattern.search(line)
                if not m:
                    continue
                evidence = m.group(0)
                findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "confidence": "high",
                    "file": str(fp),
                    "line": line_no,
                    "evidence_masked": mask_evidence(evidence),
                    "recommendation": rule.recommendation,
                })

            # 2) Medium-confidence entropy rule (catch unknown tokens)
            for tok in TOKEN_RE.findall(line):
                if looks_like_high_entropy_token(tok):
                    findings.append({
                        "rule_id": "SEC-ENTROPY-TOKEN",
                        "title": "Possible high-entropy secret/token (heuristic)",
                        "severity": "medium",
                        "confidence": "medium",
                        "file": str(fp),
                        "line": line_no,
                        "evidence_masked": mask_evidence(tok),
                        "recommendation": "If this is a real secret, rotate it and move it to environment variables/secret manager.",
                    })

    return findings


def mask_evidence(val: str) -> str:
    if len(val) <= 6:
        return "*" * len(val)
    return f"{val[:3]}***{val[-3:]}"
