import sys

import pytest

from websec_auditor.cli import main


@pytest.mark.parametrize("argv", [
    ["websec-auditor", "--lab", "https://example.test/"],
    ["websec-auditor", "--lab", "http://localhost:8765/insecure"],
    ["websec-auditor", "--lab", "http://127.0.0.1:8765/unknown"],
])
def test_cli_rejects_invalid_lab_destinations(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1


def test_cli_does_not_allow_lab_server_with_url(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "http://127.0.0.1:8765/insecure", "--lab-server"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
