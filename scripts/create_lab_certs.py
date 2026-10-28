"""Generate a short-lived LOCAL-ONLY CA and HTTPS server certificate.

Requires OpenSSL CLI. Never install this CA in a global trust store or commit
the generated private keys/certificates to Git.
"""

import argparse
import os
import subprocess
from pathlib import Path


def create_certificates(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = ("ca.key", "ca.crt", "server.key", "server.csr", "server.crt", "server.ext")
    if any((directory / name).exists() for name in names):
        raise FileExistsError("Certificate files already exist. Use a different directory to regenerate.")

    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.crt"
    server_key = directory / "server.key"
    server_csr = directory / "server.csr"
    server_crt = directory / "server.crt"
    ext = directory / "server.ext"

    def run(*args: str) -> None:
        subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL)

    run(
        "req", "-new", "-x509", "-sha256", "-days", "30",
        "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca_crt,
        "-subj", "/CN=WebSec Auditor Local Lab CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    run(
        "req", "-new", "-sha256",
        "-newkey", "rsa:2048", "-nodes", "-keyout", server_key,
        "-out", server_csr, "-subj", "/CN=127.0.0.1",
    )
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1\n",
        encoding="utf-8",
    )
    run(
        "x509", "-req", "-sha256", "-days", "7",
        "-in", server_csr, "-CA", ca_crt, "-CAkey", ca_key,
        "-CAcreateserial", "-out", server_crt, "-extfile", ext,
    )
    for secret in (ca_key, server_key):
        secret.chmod(0o600)
    print(f"Created local lab certificates in {directory.resolve()}")
    print("Do NOT install ca.crt system-wide. Only pass it using --ca-file.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local-only lab TLS certificates")
    parser.add_argument("--out", type=Path, default=Path(".lab-certs"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        create_certificates(args.out)
    except (FileExistsError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Certificate generation failed: {exc}\n")


if __name__ == "__main__":
    main()
