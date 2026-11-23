from pathlib import Path

import pytest

from src.ingestion.email_parser import parse_eml
from src.analysis.header_analyzer import analyze_headers


SAMPLE_DIR = Path("sample_emails")


def analyze_sample(filename):
    email_path = SAMPLE_DIR / filename
    raw_email = email_path.read_bytes()

    parsed_email = parse_eml(raw_email)
    return analyze_headers(parsed_email)


def test_benign_email_header_analysis():
    result = analyze_sample("01_benign_business.eml")

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert result["sender"]["from_domain"] == "example.com"
    assert "HDR002" not in rule_ids
    assert "HDR003" not in rule_ids


def test_password_reset_email_detects_reply_to_mismatch():
    result = analyze_sample("02_suspicious_password_reset.eml")

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR002" in rule_ids
    assert result["sender"]["from_domain"] == "example.com"
    assert result["sender"]["reply_to_domain"] == "example.net"


def test_invoice_email_detects_reply_to_mismatch():
    result = analyze_sample("03_suspicious_invoice.eml")

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR002" in rule_ids
    assert result["sender"]["from_domain"] == "example.org"
    assert result["sender"]["reply_to_domain"] == "example.net"


@pytest.mark.parametrize(
    "filename",
    [
        "01_benign_business.eml",
        "02_suspicious_password_reset.eml",
        "03_suspicious_invoice.eml",
    ],
)
def test_all_samples_produce_header_analysis(filename):
    result = analyze_sample(filename)

    assert "sender" in result
    assert "routing" in result
    assert "findings" in result
    assert "summary" in result