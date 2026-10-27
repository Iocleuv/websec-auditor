"""CLI option validation without starting a server or sending network traffic."""

import sys

import pytest

from websec_auditor.cli import main


@pytest.mark.parametrize("args", [
    ["--lab-https-server"],
    ["--lab-https-server", "--cert-file", "server.crt"],
    ["--lab-server", "--cert-file", "server.crt", "--key-file", "server.key"],
    ["--demo", "--lab-https"],
    ["https://127.0.0.1:8766/insecure", "--lab-https"],
    ["https://example.org/", "--authorized", "--ca-file", "ca.crt"],
    ["http://127.0.0.1:8765/insecure", "--lab", "--lab-https"],
])
def test_invalid_cli_combinations_raise_parser_error(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", *args])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
