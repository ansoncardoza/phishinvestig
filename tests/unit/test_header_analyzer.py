
import pytest

from src.analysis.header_analyzer import (
    _extract_domain,
    analyze_headers,
)


def create_parsed_email(
    from_address="sender@example.com",
    reply_to_address=None,
    return_path="sender@example.com",
    received_headers=None,
):
    return {
        "metadata": {
            "from": (
                [{"name": "Sender", "email": from_address}]
                if from_address else []
            ),
            "reply_to": (
                [{"name": "Reply", "email": reply_to_address}]
                if reply_to_address else []
            ),
            "return_path": return_path or "",
        },
        "headers": [
            {"name": "Received", "value": value}
            for value in (received_headers or [])
        ],
    }


def test_extracts_domain_from_email_address():
    assert _extract_domain("analyst@example.com") == "example.com"


def test_domain_extraction_is_case_insensitive():
    assert _extract_domain("Analyst@Example.COM") == "example.com"


@pytest.mark.parametrize(
    "address",
    [None, "", "invalid-address", "analyst@localhost"],
)
def test_invalid_addresses_return_no_domain(address):
    assert _extract_domain(address) is None


def test_detects_reply_to_domain_mismatch():
    result = analyze_headers(
        create_parsed_email(
            from_address="support@example.com",
            reply_to_address="attacker@malicious.net",
        )
    )

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR002" in rule_ids


def test_matching_reply_to_domain_has_no_mismatch_finding():
    result = analyze_headers(
        create_parsed_email(
            from_address="support@example.com",
            reply_to_address="helpdesk@example.com",
        )
    )

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR002" not in rule_ids


def test_detects_return_path_domain_mismatch():
    result = analyze_headers(
        create_parsed_email(
            from_address="sender@example.com",
            return_path="bounce@different.net",
        )
    )

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR003" in rule_ids


def test_detects_missing_sender_address():
    result = analyze_headers(
        create_parsed_email(from_address=None)
    )

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR001" in rule_ids


def test_extracts_received_headers():
    result = analyze_headers(
        create_parsed_email(
            received_headers=[
                "from mail.example.net by mx.example.com",
                "from relay.example.org by mail.example.net",
            ]
        )
    )

    assert result["routing"]["received_header_count"] == 2


def test_detects_missing_received_headers():
    result = analyze_headers(create_parsed_email())

    rule_ids = [item["rule_id"] for item in result["findings"]]

    assert "HDR004" in rule_ids


def test_returns_finding_summary():
    result = analyze_headers(
        create_parsed_email(
            from_address="support@example.com",
            reply_to_address="attacker@malicious.net",
            return_path="bounce@different.net",
            received_headers=["from mx.example.com"],
        )
    )

    assert result["summary"]["total_findings"] == 2
    assert result["summary"]["medium"] == 1
    assert result["summary"]["low"] == 1


def test_matching_sender_domains_do_not_trigger_mismatch():
    result = analyze_headers(
        create_parsed_email(
            from_address="sender@example.com",
            reply_to_address="helpdesk@example.com",
            return_path="bounce@example.com",
            received_headers=["from mx.example.com"],
        )
    )

    assert result["findings"] == []
