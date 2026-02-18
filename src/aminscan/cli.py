from __future__ import annotations
from .web_scanner import scan_web


import argparse
import sys
from pathlib import Path

from .secrets_scanner import scan_secrets

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def findings_hit_threshold(findings: list[dict], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    for f in findings:
        sev = f.get("severity", "low").lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold:
            return True
    return False


def render_markdown(findings: list[dict]) -> str:
    if not findings:
        return "# AminScan Report\n\n✅ No secrets detected.\n"

    lines: list[str] = []
    lines.append("# AminScan Report\n")
    lines.append(f"Findings: **{len(findings)}**\n")

    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {f['title']}")

        conf = f.get("confidence", "high").upper()
        lines.append(f"- Severity: **{f['severity'].upper()}**")
        lines.append(f"- Confidence: **{conf}**")
        lines.append(f"- Location: `{f['file']}:{f['line']}`")
        lines.append(f"- Evidence (masked): `{f['evidence_masked']}`")
        lines.append(f"- Fix: {f['recommendation']}\n")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(prog="aminscan")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a folder for leaked secrets (basic)")
    scan.add_argument("--path", default=".", help="Path to scan (default: .)")
    scan.add_argument("--no-entropy", action="store_true", help="Disable entropy-based heuristic detection")
    scan.add_argument("--url", default=None, help="Optional URL to scan for basic web misconfigurations")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Exit with code 1 if any finding is >= this severity",
    )
    scan.add_argument("--out", default=None, help="Write report markdown to this file")

    args = parser.parse_args()

    base = Path(args.path).resolve()
    if not base.exists():
        raise SystemExit(f"Path not found: {base}")

    findings = scan_secrets(base, use_entropy=not args.no_entropy)

    if args.url:
        web_findings = scan_web(args.url)
        findings.extend(web_findings)

    # Console output (human-friendly)
    if not findings:
        print("AminScan ✅ No secrets detected.")
    else:
        print(f"AminScan ⚠️ Findings: {len(findings)}\n")
        for f in findings:
            print(f"- [{f['severity'].upper()}] {f['title']}")
            print(f"  File: {f['file']}:{f['line']}")
            print(f"  Evidence: {f['evidence_masked']}")
            print(f"  Confidence: {f.get('confidence', 'high').upper()}")
            print(f"  Fix: {f['recommendation']}\n")

    # Markdown report output (CI-friendly)
    md = render_markdown(findings)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")

    # Exit code (CI gate)
    sys.exit(1 if findings_hit_threshold(findings, args.fail_on) else 0)
