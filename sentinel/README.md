# 🛡️ Sentinel

**A DevSecOps-first secrets and misconfiguration scanner for codebases.**

Sentinel scans your source code, configuration files, Dockerfiles, and CI/CD pipelines for hardcoded secrets, dangerous misconfigurations, and common security anti-patterns — and reports them with actionable remediation guidance.

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ╚════██║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  Sentinel: DevSecOps Secret & Misconfiguration Scanner
```

---

## Why Sentinel?

Hardcoded secrets and misconfigurations are among the most common root causes of security breaches. Tools like `git-secrets` are git-hook-only; commercial scanners like Snyk or Semgrep require accounts and internet connectivity. Sentinel is a **zero-dependency, offline-first** Python CLI you can drop into any pipeline.

It produces:
- Human-readable **terminal output** (with ANSI colour)
- Machine-readable **JSON** for dashboards and SIEM ingestion
- **SARIF 2.1.0** for native GitHub Advanced Security / Code Scanning integration

---

## Features

| Category | What it catches |
|---|---|
| **Secrets** | AWS keys, GitHub tokens, Stripe keys, Slack tokens, JWTs, private keys, DB connection strings, hardcoded passwords |
| **Misconfigurations** | Debug mode enabled, wildcard CORS, disabled TLS verification, overly permissive file modes, HTTP in production config |
| **Dockerfile** | Running as root, `latest` tag, `ADD` vs `COPY`, secrets in build `ARG`, `curl \| bash` patterns |
| **CI/CD** | Hardcoded secrets in YAML env blocks, unpinned GitHub Actions (supply chain risk) |

---

## Quickstart

```bash
# Install
pip install -e ".[dev]"

# Scan a directory
sentinel scan ./my-project

# Scan and only report high/critical
sentinel scan ./my-project --severity high

# Export JSON report
sentinel scan ./my-project --format json --output report.json

# Export SARIF (for GitHub Code Scanning)
sentinel scan ./my-project --format sarif --output results.sarif

# Fail the build if issues are found (CI/CD mode)
sentinel scan ./my-project --severity high --fail-on-findings

# List all detection rules
sentinel rules

# List rules by category
sentinel rules --category dockerfile
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Sentinel security scan
  run: |
    pip install sentinel-scanner
    sentinel scan . --severity high --format sarif --output sentinel.sarif --fail-on-findings

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: sentinel.sarif
```

Findings appear directly in the **GitHub Security → Code Scanning** tab.

### GitLab CI

```yaml
security-scan:
  script:
    - pip install sentinel-scanner
    - sentinel scan . --severity medium --format json --output sentinel-report.json
  artifacts:
    paths: [sentinel-report.json]
```

---

## Configuration

Create a `.sentinel.yml` in your project root:

```yaml
exclude:
  - node_modules
  - .venv
  - dist

min_severity: low
```

Sentinel auto-detects this file when you run `sentinel scan .`

---

## Shannon Entropy Gate

For rules where false positives are common (e.g., `AWS_ACCESS_KEY`), Sentinel computes the **Shannon entropy** of the matched token. Low-entropy strings (like `AKIAIOSFODNN7EXAMPLE`) are suppressed automatically. Real secrets have high entropy.

```
H(X) = -∑ p(x) · log₂ p(x)
```

---

## Project Structure

```
sentinel/
├── sentinel/
│   ├── __init__.py      # Package metadata
│   ├── cli.py           # argparse CLI entry point
│   ├── scanner.py       # File walker + rule engine + entropy check
│   ├── rules.py         # All detection rules (regex + metadata)
│   ├── reporter.py      # Text / JSON / SARIF output renderers
│   └── config.py        # .sentinel.yml loader
├── tests/
│   └── test_scanner.py  # pytest test suite
├── .github/
│   └── workflows/
│       └── ci.yml       # CI + self-scan workflow
├── .sentinel.yml.example
├── pyproject.toml
└── README.md
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

---

## Extending with Custom Rules

Rules live in `sentinel/rules.py` as `Rule` dataclasses. Adding a new rule is as simple as:

```python
Rule(
    rule_id="MY_CUSTOM_RULE",
    category="secrets",
    description="My organisation's internal token format",
    severity="critical",
    pattern=r"MYORG-[A-Za-z0-9]{32}",
    file_extensions=[],
    remediation="Rotate this token and store it in Vault.",
)
```

---

## License

MIT © Hafiz Saad Tanvir
