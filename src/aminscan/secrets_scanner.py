from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .secrets_rules import RULES


TEXT_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".html", ".css", ".json", ".yml", ".yaml", ".toml", ".env", ".txt", ".md",
    ".ini", ".cfg"
}


def iter_candidate_files(base: Path) -> Iterable[Path]:
    # Keep it simple for now: scan files with known text extensions
    for p in base.rglob("*"):
        if p.is_file() and (p.suffix.lower() in TEXT_EXTS or p.name == ".env"):
            yield p


def scan_secrets(base: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for fp in iter_candidate_files(base):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

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
    # Never print a full secret. Show only a small hint.
    if len(val) <= 6:
        return "*" * len(val)
    return f"{val[:3]}***{val[-3:]}"
