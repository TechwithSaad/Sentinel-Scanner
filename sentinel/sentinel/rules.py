"""
sentinel/rules.py

Detection rules for secrets, misconfigurations, Dockerfile issues, and more.
Each rule is a dataclass describing a regex-based or line-based pattern to detect.
"""

from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass
class Rule:
    rule_id: str
    category: str
    description: str
    severity: str                    # low | medium | high | critical
    pattern: str                     # regex pattern
    file_extensions: list            # which file types to apply to; [] = all
    remediation: str = ""
    entropy_check: bool = False      # optionally enforce Shannon entropy gate
    _compiled: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def compile(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled

    def matches(self, line: str) -> list[re.Match]:
        return list(self.compile().finditer(line))


# ─────────────────────────────────────────────
# SECRET RULES
# ─────────────────────────────────────────────

RULES: list[Rule] = [

    # ── AWS ──
    Rule(
        rule_id="AWS_ACCESS_KEY",
        category="secrets",
        description="AWS Access Key ID detected",
        severity="critical",
        pattern=r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        file_extensions=[],
        remediation="Rotate the key immediately via AWS IAM. Use IAM roles or AWS Secrets Manager instead of hardcoded keys.",
        entropy_check=True,
    ),
    Rule(
        rule_id="AWS_SECRET_KEY",
        category="secrets",
        description="AWS Secret Access Key detected",
        severity="critical",
        pattern=r"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        file_extensions=[],
        remediation="Rotate the key immediately. Store secrets in AWS Secrets Manager or SSM Parameter Store.",
        entropy_check=True,
    ),

    # ── Generic API Keys ──
    Rule(
        rule_id="GENERIC_API_KEY",
        category="secrets",
        description="Generic API key assignment detected",
        severity="high",
        pattern=r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,64})['\"]?",
        file_extensions=[],
        remediation="Move API keys to environment variables or a secrets manager. Never hardcode credentials.",
    ),

    # ── Tokens ──
    Rule(
        rule_id="GITHUB_TOKEN",
        category="secrets",
        description="GitHub Personal Access Token detected",
        severity="critical",
        pattern=r"ghp_[A-Za-z0-9]{30,255}",
        file_extensions=[],
        remediation="Revoke the token at github.com/settings/tokens. Use GitHub Actions secrets instead.",
        entropy_check=True,
    ),
    Rule(
        rule_id="GITHUB_OAUTH_TOKEN",
        category="secrets",
        description="GitHub OAuth token detected",
        severity="critical",
        pattern=r"gho_[A-Za-z0-9]{36}",
        file_extensions=[],
        remediation="Revoke the token immediately via GitHub settings.",
    ),
    Rule(
        rule_id="SLACK_TOKEN",
        category="secrets",
        description="Slack API token detected",
        severity="critical",
        pattern=r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
        file_extensions=[],
        remediation="Revoke the token in your Slack app settings. Use environment variables.",
    ),
    Rule(
        rule_id="STRIPE_KEY",
        category="secrets",
        description="Stripe secret key detected",
        severity="critical",
        pattern=r"sk_(live|test)_[A-Za-z0-9]{24,}",
        file_extensions=[],
        remediation="Revoke and regenerate in Stripe Dashboard. Store in environment variables only.",
    ),
    Rule(
        rule_id="JWT_TOKEN",
        category="secrets",
        description="JSON Web Token (JWT) hardcoded",
        severity="high",
        pattern=r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        file_extensions=[],
        remediation="JWTs should be generated at runtime, not hardcoded. Review token expiry and signing secrets.",
    ),

    # ── Passwords ──
    Rule(
        rule_id="HARDCODED_PASSWORD",
        category="secrets",
        description="Hardcoded password assignment detected",
        severity="high",
        pattern=r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
        file_extensions=[],
        remediation="Use environment variables or a secrets vault. Never store passwords in source code.",
    ),
    Rule(
        rule_id="PRIVATE_KEY_HEADER",
        category="secrets",
        description="Private key material detected",
        severity="critical",
        pattern=r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        file_extensions=[],
        remediation="Remove private key from source control immediately. Rotate the key pair.",
    ),

    # ── Database / Connection Strings ──
    Rule(
        rule_id="DB_CONNECTION_STRING",
        category="secrets",
        description="Database connection string with credentials",
        severity="high",
        pattern=r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^:]+:[^@]+@[^\/\s]+",
        file_extensions=[],
        remediation="Move connection strings to environment variables. Use a secrets manager for production credentials.",
    ),

    # ── GCP / Azure ──
    Rule(
        rule_id="GCP_SERVICE_ACCOUNT_KEY",
        category="secrets",
        description="GCP service account private key detected",
        severity="critical",
        pattern=r'"private_key":\s*"-----BEGIN RSA PRIVATE KEY-----',
        file_extensions=[".json"],
        remediation="Remove the service account key file from source control. Use Workload Identity Federation instead.",
    ),
    Rule(
        rule_id="AZURE_STORAGE_KEY",
        category="secrets",
        description="Azure Storage Account key detected",
        severity="critical",
        pattern=r"(?i)AccountKey=[A-Za-z0-9+/=]{88}",
        file_extensions=[],
        remediation="Rotate the key in Azure Portal. Use managed identities instead of storage keys.",
    ),

    # ─────────────────────────────────────────────
    # MISCONFIGURATION RULES
    # ─────────────────────────────────────────────

    Rule(
        rule_id="DEBUG_MODE_ENABLED",
        category="misconfig",
        description="Debug mode explicitly enabled",
        severity="medium",
        pattern=r"(?i)(DEBUG\s*=\s*True|debug\s*:\s*true)",
        file_extensions=[".py", ".env", ".yml", ".yaml", ".json", ".cfg", ".ini"],
        remediation="Disable debug mode in production. Use environment-based configuration.",
    ),
    Rule(
        rule_id="WILDCARD_CORS",
        category="misconfig",
        description="Wildcard CORS policy detected (Access-Control-Allow-Origin: *)",
        severity="high",
        pattern=r"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*['\"]?",
        file_extensions=[".py", ".js", ".ts", ".go", ".rb", ".java", ".conf", ".yaml", ".yml"],
        remediation="Restrict CORS to specific trusted origins instead of using a wildcard.",
    ),
    Rule(
        rule_id="INSECURE_HTTP_SCHEME",
        category="misconfig",
        description="Hardcoded HTTP (non-HTTPS) URL found",
        severity="low",
        pattern=r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9\-\.]+",
        file_extensions=[".py", ".js", ".ts", ".env", ".yml", ".yaml", ".json"],
        remediation="Use HTTPS for all external URLs in production configurations.",
    ),
    Rule(
        rule_id="DISABLED_TLS_VERIFY",
        category="misconfig",
        description="TLS/SSL verification explicitly disabled",
        severity="high",
        pattern=r"(?i)(verify\s*=\s*False|ssl_verify\s*=\s*false|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false)",
        file_extensions=[],
        remediation="Never disable TLS verification in production. Use valid certificates and trusted CAs.",
    ),
    Rule(
        rule_id="WORLD_READABLE_FILE_PERM",
        category="misconfig",
        description="Potentially world-readable file permission (0777 or 0666)",
        severity="medium",
        pattern=r"chmod\s+(0?777|0?666|a\+rwx)",
        file_extensions=[".sh", ".bash", ".py", ".Makefile"],
        remediation="Use least-privilege permissions. Prefer 0644 for files, 0755 for executables.",
    ),

    # ─────────────────────────────────────────────
    # DOCKERFILE RULES
    # ─────────────────────────────────────────────

    Rule(
        rule_id="DOCKERFILE_ROOT_USER",
        category="dockerfile",
        description="Docker container running as root (no USER directive)",
        severity="high",
        pattern=r"^USER\s+root$",
        file_extensions=["Dockerfile", ".dockerfile"],
        remediation="Add a non-root USER instruction. Running as root violates least-privilege.",
    ),
    Rule(
        rule_id="DOCKERFILE_LATEST_TAG",
        category="dockerfile",
        description="Docker image pinned to 'latest' tag",
        severity="medium",
        pattern=r"^FROM\s+[a-zA-Z0-9\-_./]+:latest(\s|$)",
        file_extensions=["Dockerfile", ".dockerfile"],
        remediation="Pin base images to specific digests or version tags for reproducible builds.",
    ),
    Rule(
        rule_id="DOCKERFILE_ADD_INSTEAD_OF_COPY",
        category="dockerfile",
        description="ADD instruction used instead of COPY",
        severity="low",
        pattern=r"^\s*ADD\s+(?!http)",
        file_extensions=["Dockerfile", ".dockerfile"],
        remediation="Use COPY instead of ADD unless you specifically need URL fetching or tar extraction.",
    ),
    Rule(
        rule_id="DOCKERFILE_SECRET_ARG",
        category="dockerfile",
        description="Secret or password passed as Docker build ARG",
        severity="critical",
        pattern=r"(?i)ARG\s+(password|secret|token|api_key|apikey)",
        file_extensions=["Dockerfile", ".dockerfile"],
        remediation="Never pass secrets as build ARGs—they appear in image history. Use Docker Buildkit --secret instead.",
    ),
    Rule(
        rule_id="DOCKERFILE_CURL_BASH",
        category="dockerfile",
        description="Curl-pipe-to-bash pattern detected (supply chain risk)",
        severity="high",
        pattern=r"curl\s+.*\|\s*(sudo\s+)?bash",
        file_extensions=["Dockerfile", ".dockerfile", ".sh"],
        remediation="Avoid curl | bash patterns. Download, verify checksums/signatures, then execute.",
    ),

    # ─────────────────────────────────────────────
    # CI/CD RULES
    # ─────────────────────────────────────────────

    Rule(
        rule_id="CICD_SECRETS_IN_ENV",
        category="cicd",
        description="Secret hardcoded in CI/CD environment block",
        severity="high",
        pattern=r"(?i)(password|secret|token|api_key)\s*:\s*['\"]?[A-Za-z0-9\-_@#$%^&*]{8,}['\"]?",
        file_extensions=[".yml", ".yaml"],
        remediation="Use CI/CD platform secret variables (e.g., GitHub Actions Secrets, GitLab CI Variables).",
    ),
    Rule(
        rule_id="GITHUB_ACTIONS_UNPINNED",
        category="cicd",
        description="GitHub Action used without pinned commit SHA",
        severity="medium",
        pattern=r"uses:\s+[A-Za-z0-9\-_/]+@(main|master|latest|HEAD)",
        file_extensions=[".yml", ".yaml"],
        remediation="Pin third-party GitHub Actions to a specific commit SHA to prevent supply chain attacks.",
    ),
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
