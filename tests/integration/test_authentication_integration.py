
from pathlib import Path

from src.ingestion.email_parser import parse_eml
from src.analysis.authentication_analyzer import analyze_authentication


SAMPLE_DIR = Path("sample_emails")


def test_benign_sample_has_no_recorded_authentication_results():
    parsed = parse_eml(
        (SAMPLE_DIR / "01_benign_business.eml").read_bytes()
    )

    result = analyze_authentication(parsed)

    assert result["summary"] == {
        "spf": "not_evaluated",
        "dkim": "not_evaluated",
        "dmarc": "not_evaluated",
    }


def test_password_reset_sample_has_no_recorded_authentication_results():
    parsed = parse_eml(
        (SAMPLE_DIR / "02_suspicious_password_reset.eml").read_bytes()
    )

    result = analyze_authentication(parsed)

    assert all(
        status == "not_evaluated"
        for status in result["summary"].values()
    )


def test_invoice_sample_has_no_recorded_authentication_results():
    parsed = parse_eml(
        (SAMPLE_DIR / "03_suspicious_invoice.eml").read_bytes()
    )

    result = analyze_authentication(parsed)

    assert all(
        status == "not_evaluated"
        for status in result["summary"].values()
    )


def test_parser_and_analyzer_process_authentication_headers():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: analyst@example.net\r\n"
        b"Subject: Authentication Test\r\n"
        b"Authentication-Results: mx.example.net; "
        b"spf=pass smtp.mailfrom=example.com; "
        b"dkim=pass header.d=example.com; "
        b"dmarc=pass header.from=example.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Test message.\r\n"
    )

    parsed = parse_eml(raw_email)
    result = analyze_authentication(parsed)

    assert result["summary"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    }
