from aminscan.cli import render_markdown

def test_markdown_no_findings():
    md = render_markdown([])
    assert "AminScan Report" in md
    assert "No findings" in md or "✅" in md

def test_markdown_with_findings():
    findings = [{
        "rule_id": "SEC-ENTROPY-TOKEN",
        "title": "Possible high-entropy secret/token (heuristic)",
        "severity": "medium",
        "confidence": "medium",
        "file": "file.txt",
        "line": 10,
        "evidence_masked": "R4n***+==",
        "recommendation": "Rotate if real."
    }]
    md = render_markdown(findings)
    assert "Summary" in md
    assert "Findings" in md
    assert "SEC-ENTROPY-TOKEN" in md
