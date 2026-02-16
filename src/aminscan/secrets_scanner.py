from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

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

        # If someone committed a .env file, raise a warning (even if it has no match)
        if fp.name == ".env":
            findings.append({
                "rule_id": "SEC-DOTENV",
                "title": ".env file detected (may contain secrets)",
                "severity": "medium",
                "file": str(fp),
                "line": 1,
                "evidence_masked": ".env",
                "recommendation": "Remove .env from repo and add it to .gitignore. Rotate any exposed values.",
            })

        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                m = rule.pattern.search(line)
                if not m:
                    continue

                evidence = m.group(0)
                findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "file": str(fp),
                    "line": line_no,
                    "evidence_masked": mask_evidence(evidence),
                    "recommendation": rule.recommendation,
                })

    return findings


def mask_evidence(val: str) -> str:
    if len(val) <= 6:
        return "*" * len(val)
    return f"{val[:3]}***{val[-3:]}"
