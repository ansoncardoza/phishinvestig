
import pytest

from src.analysis.authentication_analyzer import (
    analyze_authentication,
)


def create_parsed_email(headers=None):
    return {
        "headers": headers or [],
    }


def test_missing_authentication_results_are_not_evaluated():
    result = analyze_authentication(create_parsed_email())

    assert result["summary"] == {
        "spf": "not_evaluated",
        "dkim": "not_evaluated",
        "dmarc": "not_evaluated",
    }


def test_extracts_all_three_passing_results():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.example.com; "
                    "spf=pass smtp.mailfrom=example.com; "
                    "dkim=pass header.d=example.com; "
                    "dmarc=pass header.from=example.com"
                ),
            }
        ])
    )

    assert result["summary"] == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    }


def test_detects_authentication_failures():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.example.com; "
                    "spf=fail; "
                    "dkim=fail; "
                    "dmarc=fail"
                ),
            }
        ])
    )

    assert result["summary"] == {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
    }


@pytest.mark.parametrize(
    "status",
    [
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    ],
)
def test_recognizes_supported_authentication_statuses(status):
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": f"mx.example.com; spf={status}",
            }
        ])
    )

    assert result["summary"]["spf"] == status


def test_extracts_spf_from_received_spf_header():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Received-SPF",
                "value": "pass (mx.example.com: domain of example.com)",
            }
        ])
    )

    assert result["summary"]["spf"] == "pass"
    assert result["summary"]["dkim"] == "not_evaluated"
    assert result["summary"]["dmarc"] == "not_evaluated"


def test_detects_dkim_signature_presence_without_claiming_pass():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "DKIM-Signature",
                "value": "v=1; a=rsa-sha256; d=example.com; s=mail",
            }
        ])
    )

    assert result["evidence"]["dkim_signature_present"] is True
    assert result["summary"]["dkim"] == "not_evaluated"


def test_preserves_multiple_authentication_results_headers():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "mx1.example.com; spf=pass",
            },
            {
                "name": "Authentication-Results",
                "value": "mx2.example.com; dkim=pass",
            },
        ])
    )

    assert len(
        result["evidence"]["authentication_results_headers"]
    ) == 2

    assert result["summary"]["spf"] == "pass"
    assert result["summary"]["dkim"] == "pass"


def test_ignores_malformed_authentication_status():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "mx.example.com; spf=unknown",
            }
        ])
    )

    assert result["summary"]["spf"] == "not_evaluated"


def test_header_name_matching_is_case_insensitive():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "aUtHeNtIcAtIoN-ReSuLtS",
                "value": "mx.example.com; dmarc=pass",
            }
        ])
    )

    assert result["summary"]["dmarc"] == "pass"

def test_detects_conflicting_spf_results():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "mx1.example.com; spf=pass",
            },
            {
                "name": "Authentication-Results",
                "value": "mx2.example.com; spf=fail",
            },
        ])
    )

    assert len(
        result["authentication"]["spf"]["results"]
    ) == 2


def test_trusts_configured_authentication_server():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "mx.company.com; spf=pass",
            }
        ]),
        trusted_authserv_ids={"mx.company.com"},
    )

    spf_result = result["authentication"]["spf"]["results"][0]

    assert spf_result["authserv_id"] == "mx.company.com"
    assert spf_result["trust_status"] == "trusted"
    assert spf_result["verification_status"] == "not_performed"


def test_marks_unconfigured_authentication_server_untrusted():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "fake.example.net; spf=pass",
            }
        ]),
        trusted_authserv_ids={"mx.company.com"},
    )

    spf_result = result["authentication"]["spf"]["results"][0]

    assert spf_result["authserv_id"] == "fake.example.net"
    assert spf_result["trust_status"] == "untrusted"


def test_marks_missing_authserv_id_as_unknown():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Authentication-Results",
                "value": "; spf=pass",
            }
        ]),
        trusted_authserv_ids={"mx.company.com"},
    )

    spf_result = result["authentication"]["spf"]["results"][0]

    assert spf_result["authserv_id"] is None
    assert spf_result["trust_status"] == "unknown"


def test_received_spf_is_not_automatically_trusted():
    result = analyze_authentication(
        create_parsed_email([
            {
                "name": "Received-SPF",
                "value": "pass (mx.company.com: domain of example.com)",
            }
        ]),
        trusted_authserv_ids={"mx.company.com"},
    )

    spf_result = result["authentication"]["spf"]["results"][0]

    assert spf_result["status"] == "pass"
    assert spf_result["authserv_id"] is None
    assert spf_result["trust_status"] == "unknown"
    assert spf_result["verification_status"] == "not_performed"