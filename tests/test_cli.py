import json
import sys

import pytest

from websec_auditor.cli import main


def test_demo_cli_prints_json_offline(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "--demo"])
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["demo"] is True
    assert report["findings"]
    assert report["note"].startswith("Synthetic")


def test_demo_cli_writes_file(monkeypatch, tmp_path):
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "--demo", "--output", str(output)])
    main()
    assert json.loads(output.read_text(encoding="utf-8"))["demo"] is True


def test_live_cli_requires_authorization(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["websec-auditor", "https://example.test"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2
