"""Command-line interface for WebSec Auditor."""

import argparse
import json
import sys
from pathlib import Path

from websec_auditor.demo import demo_report
from websec_auditor.lab import serve_lab
from websec_auditor.scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive security audit of an authorized website")
    parser.add_argument("url", nargs="?", help="Authorized HTTPS URL or a fixed local lab URL")
    parser.add_argument("--demo", action="store_true", help="Synthetic offline report")
    parser.add_argument("--profile", choices=("insecure", "hardened"), help="Offline demo profile")
    parser.add_argument("--lab-server", action="store_true", help="Run the HTTP lab on 127.0.0.1:8765")
    parser.add_argument("--lab-https-server", action="store_true", help="Run the HTTPS lab on 127.0.0.1:8766")
    parser.add_argument("--cert-file", type=Path, help="HTTPS lab server certificate")
    parser.add_argument("--key-file", type=Path, help="HTTPS lab server private key")
    parser.add_argument("--lab", action="store_true", help="Audit the HTTP loopback lab")
    parser.add_argument("--lab-https", action="store_true", help="Audit the HTTPS loopback lab")
    parser.add_argument("--ca-file", type=Path, help="Local lab CA certificate (only with --lab-https)")
    parser.add_argument("--authorized", action="store_true", help="Confirm ownership or explicit authorization")
    parser.add_argument("--output", type=Path, help="Save a JSON report")
    args = parser.parse_args()

    if args.lab_server or args.lab_https_server:
        if (
            args.lab_server and args.lab_https_server
            or args.url or args.demo or args.lab or args.lab_https
            or args.profile or args.authorized or args.output or args.ca_file
        ):
            parser.error("Server options cannot be combined with scanning options.")
        if args.lab_https_server and (not args.cert_file or not args.key_file):
            parser.error("--lab-https-server requires --cert-file and --key-file.")
        if args.lab_server and (args.cert_file or args.key_file):
            parser.error("--cert-file and --key-file apply only to --lab-https-server.")
        try:
            serve_lab(https=args.lab_https_server, cert_file=args.cert_file, key_file=args.key_file)
        except (OSError, ValueError) as exc:
            parser.exit(1, f"Cannot start lab: {exc}\n")
        return

    if args.cert_file or args.key_file:
        parser.error("--cert-file and --key-file apply only to --lab-https-server.")

    if args.demo:
        if args.url is not None or args.lab or args.lab_https or args.authorized or args.ca_file:
            parser.error("--demo cannot be combined with a URL or scanning flags.")
    else:
        if args.profile is not None:
            parser.error("--profile can only be used with --demo.")
        if args.url is None:
            parser.error("Provide an authorized URL, --demo, --lab-server or --lab-https-server.")
        if args.lab and args.lab_https:
            parser.error("Choose either --lab or --lab-https.")
        if args.ca_file and not args.lab_https:
            parser.error("--ca-file is supported only with --lab-https.")
        if args.lab_https and not args.ca_file:
            parser.error("--lab-https requires --ca-file.")
        if args.authorized and (args.lab or args.lab_https):
            parser.error("--authorized must not be combined with lab modes.")
        if not (args.authorized or args.lab or args.lab_https):
            parser.error("Confirm --authorized, or use a fixed local lab mode.")

    try:
        report = (
            demo_report(args.profile or "insecure")
            if args.demo
            else scan(
                args.url,
                allow_local_http=args.lab,
                allow_local_https=args.lab_https,
                ca_file=args.ca_file,
            )
        )
        text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(text, encoding="utf-8")
            print(f"Report saved to {args.output}")
        else:
            print(text, end="")
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
