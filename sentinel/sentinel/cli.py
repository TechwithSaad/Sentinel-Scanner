"""
Sentinel CLI - Entry point for the secrets & misconfiguration scanner.
"""

import argparse
import sys
import os
from pathlib import Path

from sentinel.scanner import Scanner
from sentinel.reporter import Reporter
from sentinel.config import load_config


BANNER = r"""
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

  DevSecOps Secret & Misconfiguration Scanner
  ─────────────────────────────────────────────
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel: Scan codebases for secrets, misconfigurations, and security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel scan ./my-project
  sentinel scan ./my-project --output report.json --format json
  sentinel scan ./my-project --severity high
  sentinel scan ./my-project --exclude node_modules,dist
  sentinel scan ./my-project --config .sentinel.yml
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for issues")
    scan_parser.add_argument("path", type=str, help="Path to the directory or file to scan")
    scan_parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Output file path (default: stdout)"
    )
    scan_parser.add_argument(
        "--format", "-f", choices=["text", "json", "sarif"], default="text",
        help="Output format (default: text)"
    )
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity level to report"
    )
    scan_parser.add_argument(
        "--exclude", "-e", type=str, default=None,
        help="Comma-separated list of directories/files to exclude"
    )
    scan_parser.add_argument(
        "--config", "-c", type=str, default=None,
        help="Path to custom config file (.sentinel.yml)"
    )
    scan_parser.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the ASCII banner"
    )
    scan_parser.add_argument(
        "--fail-on-findings", action="store_true",
        help="Exit with code 1 if any findings are found (useful in CI/CD)"
    )

    # rules subcommand
    rules_parser = subparsers.add_parser("rules", help="List all detection rules")
    rules_parser.add_argument(
        "--category", type=str, default=None,
        help="Filter rules by category (secrets, misconfig, dockerfile, etc.)"
    )

    return parser


def cmd_scan(args) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"[ERROR] Path does not exist: {args.path}", file=sys.stderr)
        return 2

    config = load_config(args.config)

    exclude = []
    if args.exclude:
        exclude = [e.strip() for e in args.exclude.split(",")]

    scanner = Scanner(config=config, exclude=exclude, min_severity=args.severity)
    findings = scanner.scan(target)

    reporter = Reporter(format=args.format, output_path=args.output)
    reporter.report(findings, scanned_path=str(target))

    if args.fail_on_findings and findings:
        return 1
    return 0


def cmd_rules(args):
    from sentinel.rules import RULES
    category_filter = args.category

    print(f"\n{'Category':<20} {'Rule ID':<30} {'Severity':<10} {'Description'}")
    print("─" * 90)

    printed = 0
    for rule in RULES:
        if category_filter and rule.category.lower() != category_filter.lower():
            continue
        print(f"{rule.category:<20} {rule.rule_id:<30} {rule.severity:<10} {rule.description}")
        printed += 1

    print(f"\n{printed} rule(s) listed.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        if not getattr(args, "no_banner", False):
            print(BANNER)
        sys.exit(cmd_scan(args))

    elif args.command == "rules":
        cmd_rules(args)

    else:
        print(BANNER)
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
