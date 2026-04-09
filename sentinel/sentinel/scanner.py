"""
sentinel/scanner.py

Core scanning engine. Walks the target path, applies rules, and collects findings.
"""

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.rules import Rule, RULES, SEVERITY_ORDER

# File extensions (and exact names) that are safe to scan as text
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java",
    ".sh", ".bash", ".zsh", ".env", ".cfg", ".ini", ".conf",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".html", ".tf",
    ".hcl", ".properties", ".gradle", ".rs", ".php", ".cs",
    ".dockerfile", ".md", ".txt", ".csv",
}
TEXT_EXACT_NAMES = {"Dockerfile", "Makefile", ".env", ".envrc", "Jenkinsfile"}

# Directories that are almost never useful to scan
DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".venv", "venv",
    "env", "dist", "build", ".mypy_cache", ".pytest_cache", "coverage",
    ".eggs", "*.egg-info",
}

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB – skip larger files


@dataclass
class Finding:
    rule: Rule
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    entropy: Optional[float] = None


@dataclass
class Scanner:
    config: dict = field(default_factory=dict)
    exclude: list = field(default_factory=list)
    min_severity: Optional[str] = None

    def _should_scan_file(self, path: Path, exclude_set: set) -> bool:
        # Skip excluded paths
        for part in path.parts:
            if part in exclude_set:
                return False
        # Skip binary / large files
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return False
        # Accept by extension or exact filename
        if path.suffix.lower() in TEXT_EXTENSIONS:
            return True
        name_lower = path.name.lower()
        if path.name in TEXT_EXACT_NAMES:
            return True
        # Also catch files whose name ends with a known exact name (e.g. tmpXXXDockerfile)
        if any(name_lower.endswith(n.lower()) for n in TEXT_EXACT_NAMES):
            return True
        return False

    def _applicable_rules(self, path: Path) -> list[Rule]:
        """Return rules that apply to this file based on extension/name."""
        suffix = path.suffix.lower()
        name = path.name
        name_lower = name.lower()
        filtered = []
        for rule in RULES:
            # Severity gate
            if self.min_severity:
                if SEVERITY_ORDER.get(rule.severity, 0) < SEVERITY_ORDER.get(self.min_severity, 0):
                    continue
            # Extension gate: match on suffix, exact name, or name ending with
            # a known filename (e.g. tmpXXXDockerfile still counts as Dockerfile)
            if rule.file_extensions:
                exts_lower = [e.lower() for e in rule.file_extensions]
                matched = (
                    suffix in exts_lower
                    or name in rule.file_extensions
                    or any(name_lower.endswith(e.lower()) for e in rule.file_extensions)
                )
                if not matched:
                    continue
            filtered.append(rule)
        return filtered

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _scan_file(self, path: Path, rules: list[Rule]) -> list[Finding]:
        findings = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for rule in rules:
                matches = rule.matches(line)
                for match in matches:
                    matched_text = match.group(0)
                    entropy = None

                    if rule.entropy_check:
                        entropy = self.shannon_entropy(matched_text)
                        # Entropy < 3.5 likely means a placeholder/example value
                        if entropy < 3.5:
                            continue

                    findings.append(Finding(
                        rule=rule,
                        file_path=str(path),
                        line_number=line_no,
                        line_content=line.rstrip(),
                        matched_text=matched_text,
                        entropy=entropy,
                    ))
        return findings

    def scan(self, target: Path) -> list[Finding]:
        exclude_set = DEFAULT_EXCLUDE_DIRS | set(self.exclude)

        # Custom exclusions from config
        if "exclude" in self.config:
            exclude_set |= set(self.config["exclude"])

        all_findings: list[Finding] = []

        if target.is_file():
            rules = self._applicable_rules(target)
            if rules:
                all_findings.extend(self._scan_file(target, rules))
        else:
            for dirpath, dirnames, filenames in os.walk(target):
                # Prune excluded dirs in-place so os.walk skips them
                dirnames[:] = [d for d in dirnames if d not in exclude_set]

                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    if not self._should_scan_file(filepath, exclude_set):
                        continue
                    rules = self._applicable_rules(filepath)
                    if rules:
                        all_findings.extend(self._scan_file(filepath, rules))

        # Sort: critical first, then high, medium, low
        all_findings.sort(
            key=lambda f: SEVERITY_ORDER.get(f.rule.severity, 0),
            reverse=True,
        )
        return all_findings
