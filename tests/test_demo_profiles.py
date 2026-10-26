import json
import sys

import pytest

from websec_auditor.cli import main
from websec_auditor.demo import demo_report


def test_insecure_demo_has_expected_findings():
    report = demo_report()
    assert report["demo"] is True
    assert report["profile"] == "insecure"
    assert len(report["findings"]) == 7
    assert "REDACTED" not in str(report["findings"])


def test_hardened_demo_has_no_findings():
    report = demo_report("hardened")
    assert report["profile"] == "hardened"
    assert report["findings"] == []


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        demo_report("arbitrary")


def test_cli_hardened_demo(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "--demo", "--profile", "hardened"])
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["profile"] == "hardened"
    assert report["findings"] == []


def test_cli_rejects_profile_without_demo(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "https://example.test", "--authorized", "--profile", "hardened"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2
