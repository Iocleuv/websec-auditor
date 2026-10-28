"""Reports should summarize findings without implying a security grade."""

import pytest

from websec_auditor.demo import demo_report
from websec_auditor.reporting import enrich_report


def test_demo_insecure_summary_is_consistent():
    report = demo_report("insecure")
    assert report["summary"]["total_findings"] == 7
    assert report["summary"]["by_severity"] == {
        "critical": 0, "high": 0, "medium": 3, "low": 4, "info": 0
    }
    assert report["methodology"]["mode"] == "offline_demo"
    assert report["methodology"]["requests_sent"] == 0
    assert "Synthetic" in report["note"]
    assert "REDACTED" not in str(report["findings"])


def test_hardened_report_has_zero_findings_but_explicit_limitations():
    report = demo_report("hardened")
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["by_severity"] == {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    assert any("Zero findings" in text for text in report["methodology"]["limitations"])
    assert "score" not in report
    assert "grade" not in report


def test_unrecognized_severity_remains_visible_in_summary():
    report = enrich_report(
        {"findings": [
            {"check": "example", "severity": "unexpected"},
            {"check": "example2", "severity": "medium"},
        ]},
        mode="authorized_https",
    )
    assert report["summary"]["total_findings"] == 2
    assert report["summary"]["by_severity"]["unexpected"] == 1
    assert report["summary"]["by_severity"]["medium"] == 1
    assert report["methodology"]["requests_sent"] == 1


def test_local_https_methodology_mentions_tls_and_hsts_limitations():
    result = enrich_report({"findings": []}, mode="local_https_lab")
    assert result["methodology"]["requests_sent"] == 1
    assert any("TLS" in text for text in result["methodology"]["limitations"])
    assert any("IP-literal" in text for text in result["methodology"]["limitations"])


def test_local_http_methodology_does_not_claim_certificate_validation():
    result = enrich_report({"findings": []}, mode="local_http_lab")
    assert result["methodology"]["requests_sent"] == 1
    assert all("TLS" not in text for text in result["methodology"]["limitations"])


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        enrich_report({"findings": []}, mode="unrecognized")
