from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .secrets_scanner import scan_secrets
from .web_scanner import scan_web

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def findings_hit_threshold(findings: list[dict], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold:
            return True
    return False


def summarize(findings: list[dict]) -> dict:
    sev = Counter()
    cat = Counter()
    for f in findings:
        sev[(f.get("severity") or "low").lower()] += 1

        rule_id = (f.get("rule_id") or "").strip()
        prefix = rule_id.split("-")[0] if rule_id else "OTHER"
        cat[prefix] += 1

    return {
        "by_severity": dict(sev),
        "by_category": dict(cat),
        "total": len(findings),
    }


def render_json(findings: list[dict], meta: dict, version: str) -> str:
    payload = {
        "tool": "AminScan",
        "version": version,
        "meta": meta,
        "summary": summarize(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2)


def render_markdown(findings: list[dict]) -> str:
    lines: list[str] = []
    lines.append("# AminScan Report\n")

    if not findings:
        lines.append("✅ No findings.\n")
        return "\n".join(lines)

    # Summary
    s = summarize(findings)
    bs = s["by_severity"]
    lines.append("## Summary\n")
    lines.append(f"- Total findings: **{s['total']}**")
    lines.append(
        f"- Critical: **{bs.get('critical', 0)}**, High: **{bs.get('high', 0)}**, "
        f"Medium: **{bs.get('medium', 0)}**, Low: **{bs.get('low', 0)}**\n"
    )

    # Details
    lines.append("## Findings\n")
    for i, f in enumerate(findings, 1):
        title = f.get("title", "Finding")
        severity = (f.get("severity") or "low").upper()
        confidence = (f.get("confidence") or "high").upper()

        file_path = f.get("file")
        line_no = f.get("line")
        location = ""
        if file_path:
            location = str(file_path)
            if line_no is not None:
                location += f":{line_no}"

        lines.append(f"### {i}. {title}")
        lines.append(f"- Severity: **{severity}**")
        lines.append(f"- Confidence: **{confidence}**")
        if location:
            lines.append(f"- Location: `{location}`")
        if f.get("rule_id"):
            lines.append(f"- Rule: `{f['rule_id']}`")
        if f.get("evidence_masked"):
            lines.append(f"- Evidence (masked): `{f['evidence_masked']}`")
        if f.get("recommendation"):
            lines.append(f"- Fix: {f['recommendation']}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    VERSION = "0.0.4"

    parser = argparse.ArgumentParser(prog="aminscan")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a folder for leaked secrets and/or scan a URL for web misconfigurations")
    scan.add_argument("--path", default=".", help="Path to scan (default: .)")
    scan.add_argument("--no-entropy", action="store_true", help="Disable entropy-based heuristic detection")
    scan.add_argument("--url", default=None, help="Optional URL to scan for basic web misconfigurations")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Exit with code 1 if any finding is >= this severity",
    )
    scan.add_argument("--out-md", default=None, help="Write Markdown report to this file")
    scan.add_argument("--out-json", default=None, help="Write JSON report to this file")

    args = parser.parse_args()

    base = Path(args.path).resolve()
    if not base.exists():
        raise SystemExit(f"Path not found: {base}")

    findings = scan_secrets(base, use_entropy=not args.no_entropy)

    if args.url:
        findings.extend(scan_web(args.url))

    # Console output
    if not findings:
        print("AminScan ✅ No findings.")
    else:
        print(f"AminScan ⚠️ Findings: {len(findings)}\n")
        for f in findings:
            print(f"- [{(f.get('severity') or 'low').upper()}] {f.get('title', 'Finding')}")
            file_path = f.get("file")
            line_no = f.get("line")
            if file_path:
                loc = f"{file_path}:{line_no}" if line_no is not None else str(file_path)
                print(f"  Location: {loc}")
            print(f"  Evidence: {f.get('evidence_masked')}")
            print(f"  Confidence: {(f.get('confidence') or 'high').upper()}")
            print(f"  Fix: {f.get('recommendation')}\n")

    # Reports
    meta = {"scanned_path": str(base), "url": args.url, "entropy_enabled": (not args.no_entropy)}

    if args.out_md:
        Path(args.out_md).write_text(render_markdown(findings), encoding="utf-8")

    if args.out_json:
        Path(args.out_json).write_text(render_json(findings, meta, VERSION), encoding="utf-8")

    # Exit code for CI gate
    sys.exit(1 if findings_hit_threshold(findings, args.fail_on) else 0)
