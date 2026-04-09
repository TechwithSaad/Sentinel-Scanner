"""
tests/test_scanner.py

Unit tests for Sentinel's scanning engine and rule matching.
"""

import pytest
from pathlib import Path
import tempfile
import os

from sentinel.scanner import Scanner, Finding
from sentinel.rules import RULES, Rule
from sentinel.reporter import Reporter
from sentinel.config import load_config


# ─── Helpers ────────────────────────────────────────────────────────────────

def make_temp_file(content: str, suffix: str = ".py") -> Path:
    """Write content to a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return Path(path)


def scan_content(content: str, suffix: str = ".py") -> list[Finding]:
    """Convenience: scan a string as if it were a file."""
    path = make_temp_file(content, suffix)
    try:
        scanner = Scanner()
        return scanner.scan(path)
    finally:
        path.unlink(missing_ok=True)


# ─── Rule matching tests ─────────────────────────────────────────────────────

class TestSecretRules:

    def test_aws_access_key_detected(self):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n'
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "AWS_ACCESS_KEY" in rule_ids

    def test_github_token_detected(self):
        content = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678"\n'
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "GITHUB_TOKEN" in rule_ids

    def test_hardcoded_password_detected(self):
        content = 'password = "SuperSecret123"\n'
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "HARDCODED_PASSWORD" in rule_ids

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "PRIVATE_KEY_HEADER" in rule_ids

    def test_db_connection_string_detected(self):
        content = 'DB_URL = "postgresql://admin:password123@prod-db.example.com/mydb"\n'
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DB_CONNECTION_STRING" in rule_ids

    def test_stripe_key_detected(self):
        content = 'stripe_key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX"\n'
        findings = scan_content(content)
        rule_ids = [f.rule.rule_id for f in findings]
        assert "STRIPE_KEY" in rule_ids

    def test_clean_file_no_findings(self):
        content = (
            'import os\n'
            'SECRET_KEY = os.environ["SECRET_KEY"]\n'
            'DB_URL = os.environ.get("DATABASE_URL")\n'
        )
        findings = scan_content(content)
        # Should find nothing - values come from env
        assert len(findings) == 0


class TestMisconfigRules:

    def test_debug_mode_detected(self):
        content = "DEBUG = True\n"
        findings = scan_content(content, suffix=".py")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DEBUG_MODE_ENABLED" in rule_ids

    def test_wildcard_cors_detected(self):
        content = 'response.headers["Access-Control-Allow-Origin"] = "*"\n'
        findings = scan_content(content, suffix=".py")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "WILDCARD_CORS" in rule_ids

    def test_disabled_tls_verify_detected(self):
        content = "requests.get(url, verify=False)\n"
        findings = scan_content(content, suffix=".py")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DISABLED_TLS_VERIFY" in rule_ids


class TestDockerfileRules:

    def test_latest_tag_detected(self):
        content = "FROM python:latest\nRUN pip install flask\n"
        findings = scan_content(content, suffix="Dockerfile")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DOCKERFILE_LATEST_TAG" in rule_ids

    def test_secret_arg_detected(self):
        content = "FROM ubuntu:22.04\nARG password\nRUN echo $password\n"
        findings = scan_content(content, suffix="Dockerfile")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DOCKERFILE_SECRET_ARG" in rule_ids

    def test_curl_bash_detected(self):
        content = "RUN curl https://install.example.com | bash\n"
        findings = scan_content(content, suffix="Dockerfile")
        rule_ids = [f.rule.rule_id for f in findings]
        assert "DOCKERFILE_CURL_BASH" in rule_ids


# ─── Scanner engine tests ─────────────────────────────────────────────────────

class TestScannerEngine:

    def test_severity_filter_excludes_low(self):
        content = 'DB_URL = "http://example.com/api"\n'
        path = make_temp_file(content, suffix=".py")
        try:
            scanner = Scanner(min_severity="high")
            findings = scanner.scan(path)
            severities = {f.rule.severity for f in findings}
            assert "low" not in severities
        finally:
            path.unlink(missing_ok=True)

    def test_directory_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text('SECRET_KEY = "hardcoded-secret-value-1234"\n')
            (root / "config.py").write_text('DB_URL = "postgresql://user:pass@host/db"\n')

            scanner = Scanner()
            findings = scanner.scan(root)
            assert len(findings) >= 1

    def test_excludes_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            nm = root / "node_modules" / "some-pkg"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";\n')
            (root / "app.py").write_text('print("hello")\n')

            scanner = Scanner()
            findings = scanner.scan(root)
            files = {f.file_path for f in findings}
            assert not any("node_modules" in fp for fp in files)

    def test_finding_includes_line_number(self):
        content = "x = 1\ny = 2\npassword = 'Secret123'\nz = 3\n"
        findings = scan_content(content)
        pw_findings = [f for f in findings if f.rule.rule_id == "HARDCODED_PASSWORD"]
        assert any(f.line_number == 3 for f in pw_findings)


# ─── Shannon entropy tests ────────────────────────────────────────────────────

class TestEntropy:

    def test_high_entropy_string(self):
        entropy = Scanner.shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert entropy > 4.0

    def test_low_entropy_placeholder(self):
        entropy = Scanner.shannon_entropy("EXAMPLE_KEY_HERE")
        assert entropy < 4.0

    def test_empty_string_entropy(self):
        assert Scanner.shannon_entropy("") == 0.0


# ─── Reporter tests ───────────────────────────────────────────────────────────

class TestReporter:

    def _make_finding(self):
        from sentinel.rules import RULES
        rule = next(r for r in RULES if r.rule_id == "HARDCODED_PASSWORD")
        return Finding(
            rule=rule,
            file_path="/tmp/app.py",
            line_number=5,
            line_content='password = "secret"',
            matched_text="secret",
        )

    def test_json_output_is_valid(self):
        import json
        reporter = Reporter(format="json")
        findings = [self._make_finding()]
        output = reporter._render_json(findings, "/tmp")
        parsed = json.loads(output)
        assert parsed["total_findings"] == 1
        assert parsed["findings"][0]["rule_id"] == "HARDCODED_PASSWORD"

    def test_sarif_output_is_valid(self):
        import json
        reporter = Reporter(format="sarif")
        findings = [self._make_finding()]
        output = reporter._render_sarif(findings, "/tmp")
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 1

    def test_text_output_contains_severity(self):
        reporter = Reporter(format="text")
        findings = [self._make_finding()]
        output = reporter._render_text(findings, "/tmp")
        assert "HIGH" in output.upper() or "MEDIUM" in output.upper() or "LOW" in output.upper()

    def test_empty_findings_text(self):
        reporter = Reporter(format="text")
        output = reporter._render_text([], "/tmp")
        assert "No issues found" in output


# ─── Config tests ─────────────────────────────────────────────────────────────

class TestConfig:

    def test_default_config_returned_when_no_file(self):
        config = load_config("/nonexistent/path/.sentinel.yml")
        assert isinstance(config, dict)
        assert "exclude" in config
