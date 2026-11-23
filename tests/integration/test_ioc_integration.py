from src.ingestion.email_parser import parse_eml
from src.analysis.ioc_extractor import extract_iocs


def test_email_parsing_and_ioc_extraction_integration():
    raw_email = b"""From: Security Team <security@example.org>
To: analyst@example.com
Subject: Suspicious account activity
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Visit https://secure.example.net/login
or investigate http://192.0.2.45/path.

Contact support@example.org.

Reported file hash:
d41d8cd98f00b204e9800998ecf8427e
"""

    parsed_email = parse_eml(raw_email)

    iocs = extract_iocs(parsed_email)

    assert iocs["urls"] == [
        "https://secure.example.net/login",
        "http://192.0.2.45/path",
    ]

    assert iocs["domains"] == [
        "secure.example.net",
    ]

    assert iocs["ipv4_addresses"] == [
        "192.0.2.45",
    ]

    assert iocs["email_addresses"] == [
        "support@example.org",
    ]

    assert iocs["file_hashes"] == [
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
        }
    ]