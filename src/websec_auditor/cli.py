import argparse
import json
import sys
from websec_auditor.scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive audit of an authorized HTTPS website")
    parser.add_argument("url", help="Authorized HTTPS URL")
    parser.add_argument("--authorized", action="store_true", help="Confirm ownership or explicit authorization")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("Use --authorized only when you own the target or have written permission.")
    try:
        print(json.dumps(scan(args.url), indent=2, ensure_ascii=False))
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
