from src.analysis.ioc_extractor import extract_urls


def test_extract_url_from_plain_text():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Please visit https://example.com/login",
            "html": "",
        },
    }

    assert extract_urls(parsed_email) == [
        "https://example.com/login"
    ]


def test_extract_url_from_html_href():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "",
            "html": '<a href="https://example.com/login">Login</a>',
        },
    }

    assert extract_urls(parsed_email) == [
        "https://example.com/login"
    ]


def test_extract_url_from_subject():
    parsed_email = {
        "metadata": {
            "subject": "Verify your account: https://example.com/verify"
        },
        "body": {"text": "", "html": ""},
    }

    assert extract_urls(parsed_email) == [
        "https://example.com/verify"
    ]


def test_remove_duplicate_urls():
    parsed_email = {
        "metadata": {"subject": "https://example.com"},
        "body": {
            "text": "Visit https://example.com",
            "html": '<a href="https://example.com">Visit</a>',
        },
    }

    assert extract_urls(parsed_email) == [
        "https://example.com"
    ]


def test_decode_html_url_entities():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "https://example.com/page?a=1&amp;b=2",
            "html": "",
        },
    }

    assert extract_urls(parsed_email) == [
        "https://example.com/page?a=1&b=2"
    ]


def test_remove_trailing_punctuation():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Visit https://example.com/login.",
            "html": "",
        },
    }

    assert extract_urls(parsed_email) == [
        "https://example.com/login"
    ]


def test_empty_email_returns_empty_list():
    assert extract_urls({}) == []


from src.analysis.ioc_extractor import extract_domains


def test_extract_domain_from_url():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Visit https://secure.example.com/login",
            "html": "",
        },
    }

    assert extract_domains(parsed_email) == [
        "secure.example.com"
    ]


def test_extract_standalone_domain():
    parsed_email = {
        "metadata": {"subject": "Visit example.org"},
        "body": {"text": "", "html": ""},
    }

    assert extract_domains(parsed_email) == [
        "example.org"
    ]


def test_extract_subdomain():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Contact mail.support.example.net",
            "html": "",
        },
    }

    assert extract_domains(parsed_email) == [
        "mail.support.example.net"
    ]


def test_deduplicate_domains():
    parsed_email = {
        "metadata": {"subject": "example.com"},
        "body": {
            "text": "https://example.com/login",
            "html": '<a href="https://example.com">Login</a>',
        },
    }

    assert extract_domains(parsed_email) == [
        "example.com"
    ]


def test_ignore_email_address_as_standalone_domain():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Contact support@example.com",
            "html": "",
        },
    }

    assert extract_domains(parsed_email) == []


def test_empty_email_returns_empty_domains():
    assert extract_domains({}) == []


from src.analysis.ioc_extractor import extract_ipv4_addresses


def test_extract_valid_ipv4_address():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Suspicious IP: 192.0.2.45",
            "html": "",
        },
    }

    assert extract_ipv4_addresses(parsed_email) == [
        "192.0.2.45"
    ]


def test_reject_invalid_ipv4_address():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Invalid IP: 999.10.20.30",
            "html": "",
        },
    }

    assert extract_ipv4_addresses(parsed_email) == []


def test_extract_multiple_ipv4_addresses():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "IPs: 192.0.2.10 and 198.51.100.20",
            "html": "",
        },
    }

    assert extract_ipv4_addresses(parsed_email) == [
        "192.0.2.10",
        "198.51.100.20",
    ]


def test_deduplicate_ipv4_addresses():
    parsed_email = {
        "metadata": {"subject": "192.0.2.45"},
        "body": {
            "text": "192.0.2.45",
            "html": "",
        },
    }

    assert extract_ipv4_addresses(parsed_email) == [
        "192.0.2.45"
    ]


def test_extract_ipv4_from_url():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Visit http://192.0.2.45/login",
            "html": "",
        },
    }

    assert extract_ipv4_addresses(parsed_email) == [
        "192.0.2.45"
    ]


def test_empty_email_returns_empty_ipv4_list():
    assert extract_ipv4_addresses({}) == []


from src.analysis.ioc_extractor import extract_email_addresses


def test_extract_email_address_from_plain_text():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Contact support@example.com for help.",
            "html": "",
        },
    }

    assert extract_email_addresses(parsed_email) == [
        "support@example.com"
    ]


def test_extract_email_address_from_subject():
    parsed_email = {
        "metadata": {
            "subject": "Reply to security@example.org"
        },
        "body": {"text": "", "html": ""},
    }

    assert extract_email_addresses(parsed_email) == [
        "security@example.org"
    ]


def test_extract_multiple_email_addresses():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": (
                "Contact admin@example.com "
                "or support@example.net"
            ),
            "html": "",
        },
    }

    assert extract_email_addresses(parsed_email) == [
        "admin@example.com",
        "support@example.net",
    ]


def test_normalize_email_addresses_to_lowercase():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Contact SUPPORT@EXAMPLE.COM",
            "html": "",
        },
    }

    assert extract_email_addresses(parsed_email) == [
        "support@example.com"
    ]


def test_deduplicate_email_addresses():
    parsed_email = {
        "metadata": {"subject": "admin@example.com"},
        "body": {
            "text": "admin@example.com",
            "html": "",
        },
    }

    assert extract_email_addresses(parsed_email) == [
        "admin@example.com"
    ]


def test_reject_invalid_email_address():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "Invalid: admin@.com and user@example",
            "html": "",
        },
    }

    assert extract_email_addresses(parsed_email) == []


def test_empty_email_returns_empty_email_addresses():
    assert extract_email_addresses({}) == []


from src.analysis.ioc_extractor import extract_file_hashes


def test_extract_md5_hash():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "MD5: d41d8cd98f00b204e9800998ecf8427e",
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == [
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
        }
    ]


def test_extract_sha1_hash():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": (
                "SHA1: "
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            ),
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == [
        {
            "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "type": "sha1",
        }
    ]


def test_extract_sha256_hash():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": (
                "SHA256: "
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == [
        {
            "value": (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
            "type": "sha256",
        }
    ]


def test_extract_multiple_hash_types():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": (
                "MD5: d41d8cd98f00b204e9800998ecf8427e "
                "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
            ),
            "html": "",
        },
    }

    results = extract_file_hashes(parsed_email)

    assert [item["type"] for item in results] == [
        "md5",
        "sha1",
    ]


def test_normalize_hash_to_lowercase():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "D41D8CD98F00B204E9800998ECF8427E",
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == [
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
        }
    ]


def test_deduplicate_file_hashes():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": (
                "d41d8cd98f00b204e9800998ecf8427e "
                "d41d8cd98f00b204e9800998ecf8427e"
            ),
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == [
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
        }
    ]


def test_reject_invalid_hash_length():
    parsed_email = {
        "metadata": {"subject": ""},
        "body": {
            "text": "d41d8cd98f00b204e9800998ecf8427",
            "html": "",
        },
    }

    assert extract_file_hashes(parsed_email) == []


def test_empty_email_returns_empty_hashes():
    assert extract_file_hashes({}) == []