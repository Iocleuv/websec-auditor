"""Command-line interface for WebSec Auditor."""

import argparse
import json
import sys
from pathlib import Path

from websec_auditor.demo import demo_report
from websec_auditor.scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive audit of an authorized HTTPS website")
    parser.add_argument("url", nargs="?", help="HTTPS URL that you own or are authorized to assess")
    parser.add_argument("--demo", action="store_true", help="Generate an offline sample report")
    parser.add_argument("--authorized", action="store_true", help="Confirm ownership or explicit authorization")
    parser.add_argument("--output", type=Path, help="Save the JSON report to a file")
    args = parser.parse_args()

    if args.demo:
        if args.url is not None:
            parser.error("--demo cannot be combined with a URL")
    elif args.url is None:
        parser.error("Provide an authorized HTTPS URL or use --demo")
    elif not args.authorized:
        parser.error("Use --authorized only when you own the target or have explicit permission")

    try:
        report = demo_report() if args.demo else scan(args.url)
        serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(serialized, encoding="utf-8")
            print(f"Report saved to {args.output}")
        else:
            print(serialized, end="")
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
