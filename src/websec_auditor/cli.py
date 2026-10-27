"""Command-line interface for WebSec Auditor."""

import argparse
import json
import sys
from pathlib import Path

from websec_auditor.demo import demo_report
from websec_auditor.lab import serve_lab
from websec_auditor.scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive audit of an authorized HTTPS website")
    parser.add_argument("url", nargs="?", help="HTTPS URL you own, or fixed loopback HTTP lab URL with --lab")
    parser.add_argument("--demo", action="store_true", help="Generate a synthetic offline sample report")
    parser.add_argument("--profile", choices=("insecure", "hardened"), default=None, help="Offline demo profile")
    parser.add_argument("--lab-server", action="store_true", help="Start a real local HTTP lab server on 127.0.0.1:8765")
    parser.add_argument("--lab", action="store_true", help="Scan the fixed local lab endpoint over HTTP")
    parser.add_argument("--authorized", action="store_true", help="Confirm ownership or explicit authorization")
    parser.add_argument("--output", type=Path, help="Save the JSON report to a file")
    args = parser.parse_args()

    if args.lab_server:
        if args.url or args.demo or args.lab or args.profile is not None or args.authorized or args.output:
            parser.error("--lab-server must be used by itself")
        try:
            serve_lab()
        except OSError as exc:
            parser.exit(1, f"Cannot start lab: {exc}\n")
        return

    if args.demo:
        if args.url is not None or args.lab or args.authorized:
            parser.error("--demo cannot be combined with a URL, --lab or --authorized")
    else:
        if args.profile is not None:
            parser.error("--profile can only be used with --demo")
        if args.url is None:
            parser.error("Provide an authorized HTTPS URL, --demo, or --lab-server")
        if args.lab and args.authorized:
            parser.error("--lab and --authorized are distinct modes")
        if not args.lab and not args.authorized:
            parser.error("Use --authorized for targets you own, or --lab for the local server")

    try:
        report = demo_report(args.profile or "insecure") if args.demo else scan(args.url, allow_local_http=args.lab)
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
