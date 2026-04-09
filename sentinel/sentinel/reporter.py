"""
sentinel/reporter.py

Renders scan findings in text (coloured terminal), JSON, or SARIF format.
SARIF (Static Analysis Results Interchange Format) is natively understood by
GitHub Advanced Security and other SAST platforms.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sentinel.rules import SEVERITY_ORDER

# ANSI colour codes – degrade gracefully if output is not a TTY
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

SEVERITY_COLOR = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[36m",   # cyan
}
GREEN  = "\033[32m"
WHITE  = "\033[97m"


def _colorize(text: str, color: str, tty: bool) -> str:
    return f"{color}{text}{RESET}" if tty else text


class Reporter:
    def __init__(self, format: str = "text", output_path: Optional[str] = None):
        self.format = format
        self.output_path = output_path
        self.tty = sys.stdout.isatty() and output_path is None

    def _out(self, content: str):
        if self.output_path:
            Path(self.output_path).write_text(content, encoding="utf-8")
            print(f"[✓] Report written to: {self.output_path}")
        else:
            print(content)

    # ── Text ──────────────────────────────────────────────────────────────────

    def _render_text(self, findings, scanned_path: str) -> str:
        t = self.tty
        lines = []
        lines.append(_colorize(f"  Scan target : {scanned_path}", DIM, t))
        lines.append(_colorize(f"  Timestamp   : {datetime.now(timezone.utc).isoformat()}", DIM, t))
        lines.append(_colorize(f"  Total issues: {len(findings)}", BOLD, t))
        lines.append("")

        if not findings:
            lines.append(_colorize("  ✓  No issues found. Great job!", GREEN, t))
            return "\n".join(lines)

        # Group by severity
        by_severity: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            by_severity.setdefault(f.rule.severity, []).append(f)

        for sev in ["critical", "high", "medium", "low"]:
            group = by_severity.get(sev, [])
            if not group:
                continue

            color = SEVERITY_COLOR.get(sev, "")
            label = _colorize(f"  [{sev.upper()}]  {len(group)} finding(s)", color, t)
            lines.append(label)
            lines.append(_colorize("  " + "─" * 70, DIM, t))

            for finding in group:
                lines.append(
                    _colorize(f"  Rule      : {finding.rule.rule_id}", BOLD, t)
                )
                lines.append(f"  File      : {finding.file_path}:{finding.line_number}")
                lines.append(f"  Detail    : {finding.rule.description}")

                # Truncate long lines for readability
                snippet = finding.line_content.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                lines.append(_colorize(f"  Snippet   : {snippet}", DIM, t))

                if finding.entropy is not None:
                    lines.append(f"  Entropy   : {finding.entropy:.2f} bits/char")

                if finding.rule.remediation:
                    lines.append(
                        _colorize(f"  Fix       : {finding.rule.remediation}", GREEN, t)
                    )
                lines.append("")

        # Summary table
        lines.append(_colorize("  Summary", BOLD, t))
        lines.append(_colorize("  " + "─" * 40, DIM, t))
        for sev in ["critical", "high", "medium", "low"]:
            count = len(by_severity.get(sev, []))
            if count:
                color = SEVERITY_COLOR.get(sev, "")
                lines.append(
                    _colorize(f"  {sev.upper():<12}", color, t) + f": {count}"
                )
        lines.append("")
        return "\n".join(lines)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _render_json(self, findings, scanned_path: str) -> str:
        output = {
            "sentinel_version": "1.0.0",
            "scanned_path": scanned_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [
                {
                    "rule_id": f.rule.rule_id,
                    "category": f.rule.category,
                    "severity": f.rule.severity,
                    "description": f.rule.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "snippet": f.line_content.strip(),
                    "matched_text": f.matched_text,
                    "entropy": round(f.entropy, 4) if f.entropy else None,
                    "remediation": f.rule.remediation,
                }
                for f in findings
            ],
        }
        return json.dumps(output, indent=2)

    # ── SARIF ─────────────────────────────────────────────────────────────────

    def _render_sarif(self, findings, scanned_path: str) -> str:
        """
        SARIF 2.1.0 – compatible with GitHub Code Scanning / Advanced Security.
        https://docs.oasis-open.org/sarif/sarif/v2.1.0/
        """
        from sentinel.rules import RULES

        rules_index = {r.rule_id: i for i, r in enumerate(RULES)}

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinel",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/TechwithSaad/sentinel",
                            "rules": [
                                {
                                    "id": r.rule_id,
                                    "name": r.rule_id,
                                    "shortDescription": {"text": r.description},
                                    "fullDescription": {"text": r.description},
                                    "helpUri": "",
                                    "properties": {
                                        "tags": [r.category],
                                        "security-severity": {
                                            "critical": "9.5",
                                            "high": "7.5",
                                            "medium": "5.0",
                                            "low": "2.5",
                                        }.get(r.severity, "5.0"),
                                    },
                                }
                                for r in RULES
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule.rule_id,
                            "ruleIndex": rules_index.get(f.rule.rule_id, 0),
                            "level": {
                                "critical": "error",
                                "high": "error",
                                "medium": "warning",
                                "low": "note",
                            }.get(f.rule.severity, "warning"),
                            "message": {
                                "text": f"{f.rule.description}. {f.rule.remediation}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": f.file_path,
                                            "uriBaseId": "%SRCROOT%",
                                        },
                                        "region": {
                                            "startLine": f.line_number,
                                            "snippet": {"text": f.line_content.strip()},
                                        },
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def report(self, findings, scanned_path: str):
        if self.format == "json":
            self._out(self._render_json(findings, scanned_path))
        elif self.format == "sarif":
            self._out(self._render_sarif(findings, scanned_path))
        else:
            self._out(self._render_text(findings, scanned_path))
