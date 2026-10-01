"""Markdown rendering of the SAST report.

The renderer runs right after a successful run, so its contract is: never raise
on model-shaped input (missing keys, wrong types), always sort by severity, and
surface the actionable parts a reviewer needs — reproduction, evidence, and
remediation.
"""

from __future__ import annotations

from report_markdown import _fence, render_markdown

FULL = {
    "report_metadata": {"codebase_path": "/src/app", "report_timestamp": "2026-08-04T00:00:00Z"},
    "findings": [
        {
            "vulnerability": "SQL injection in login",
            "description": "User input flows into a raw query.",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "confidence": "high",
            "reproduction_steps": ["POST /login with email=' OR 1=1--", "Observe auth bypass"],
            "remediation": {
                "summary": "Use parameterized queries.",
                "fix": "Replace string formatting at db.py:42 with bound parameters.",
                "code_example": "cur.execute('SELECT * FROM users WHERE email = %s', (email,))",
                "references": ["https://cwe.mitre.org/data/definitions/89.html"],
            },
            "taint_analysis": {"exploitability": "high", "impact": "Full auth bypass."},
            "evidences": [
                {
                    "path": "db.py",
                    "code_file": "db.py",
                    "snippet": "cur.execute(f'SELECT * FROM users WHERE email = {email}')",
                    "line_range": "42-42",
                }
            ],
        },
        {"vulnerability": "Verbose error page", "severity": "low", "cwe_id": "CWE-209"},
    ],
}


class TestRender:
    def test_does_not_raise_and_has_headline_sections(self):
        md = render_markdown(FULL)
        assert "# Static Analysis Security Report" in md
        assert "## Executive summary" in md
        assert "## Findings" in md

    def test_severity_sorted_critical_before_low(self):
        md = render_markdown(FULL)
        assert md.index("SQL injection") < md.index("Verbose error page")

    def test_includes_reproduction_evidence_and_remediation(self):
        md = render_markdown(FULL)
        assert "**Reproduction**" in md
        assert "auth bypass" in md
        assert "**Evidence**" in md
        assert "`db.py:42-42`" in md
        assert "**Remediation**" in md
        assert "parameterized queries" in md
        assert "cwe.mitre.org" in md

    def test_severity_count_table(self):
        md = render_markdown(FULL)
        assert "| critical | 1 |" in md
        assert "| low | 1 |" in md

    def test_scanner_grounded_findings_are_marked(self):
        report = {
            "findings": [
                {
                    "vulnerability": "Command injection",
                    "severity": "high",
                    "scanner_evidence": {
                        "rule_id": "python.lang.security.audit.subprocess-shell-true",
                        "path": "run.py",
                        "line": 12,
                    },
                },
                {"vulnerability": "Broken authz", "severity": "high"},
            ]
        }
        md = render_markdown(report)
        assert "`python.lang.security.audit.subprocess-shell-true`" in md
        # The model-discovered finding carries no scanner marking.
        assert "Broken authz" in md.split("Scanner-grounded", 1)[1]


class TestDegradesGracefully:
    def test_empty_report(self):
        md = render_markdown({})
        assert "No findings were reported." in md

    def test_missing_and_wrong_typed_fields_do_not_raise(self):
        md = render_markdown(
            {"findings": [{"vulnerability": "x"}, "not-a-dict", {"severity": None, "evidences": "nope"}]}
        )
        assert "# Static Analysis Security Report" in md

    def test_finding_without_remediation_still_renders(self):
        md = render_markdown({"findings": [{"vulnerability": "bare", "severity": "medium"}]})
        assert "bare" in md
        assert "**Remediation**" not in md.split("bare", 1)[1]


class TestFenceEscaping:
    def test_snippet_containing_backtick_fence_is_not_broken(self):
        # Evidence snippets can contain ```blocks```; the outer fence must be longer.
        opener, body, closer = _fence("text with ``` inside")
        assert opener.count("`") >= 4
        assert opener.count("`") == closer.count("`")

    def test_nested_fence_in_evidence_renders(self):
        report = {
            "findings": [
                {
                    "vulnerability": "x",
                    "severity": "high",
                    "evidences": [{"code_file": "a.md", "snippet": "```python\nx=1\n```"}],
                }
            ]
        }
        # Must not raise, and the inner fence survives.
        md = render_markdown(report)
        assert "x=1" in md
