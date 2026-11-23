import ipaddress
import re
from html import unescape


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

TRAILING_URL_PUNCTUATION = ".,;:!?"


def _extract_urls_from_text(content: str) -> list:
    """Extract HTTP and HTTPS URLs from text content."""
    if not content:
        return []

    decoded_content = unescape(content)

    matches = URL_PATTERN.findall(decoded_content)

    urls = []

    for match in matches:
        url = match.rstrip(TRAILING_URL_PUNCTUATION)

        if url:
            urls.append(url)

    return urls


def extract_urls(parsed_email: dict) -> list:
    """
    Extract URLs from email subject and body.

    Both plain-text and HTML content are inspected.
    No URLs are visited or executed.
    """
    metadata = parsed_email.get("metadata", {})
    body = parsed_email.get("body", {})

    content_sources = [
        metadata.get("subject", ""),
        body.get("text", ""),
        body.get("html", ""),
    ]

    extracted_urls = []

    for content in content_sources:
        extracted_urls.extend(
            _extract_urls_from_text(content)
        )

    # Remove duplicates while preserving original order.
    return list(dict.fromkeys(extracted_urls))

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"(?![\w.-])",
    re.IGNORECASE,
)


def extract_domains(parsed_email: dict) -> list:
    """
    Extract domain names from URLs and email content.

    Preserves subdomains, excludes IPv4 addresses,
    and does not perform DNS lookups.
    """
    metadata = parsed_email.get("metadata", {})
    body = parsed_email.get("body", {})

    content_sources = [
        metadata.get("subject", ""),
        body.get("text", ""),
        body.get("html", ""),
    ]

    domains = []

    def add_domain(candidate: str):
        candidate = candidate.lower().rstrip(".")

        try:
            ipaddress.IPv4Address(candidate)
            return
        except ipaddress.AddressValueError:
            pass

        if candidate and candidate not in domains:
            domains.append(candidate)

    # Extract hostnames from URLs.
    from urllib.parse import urlsplit

    for url in extract_urls(parsed_email):
        hostname = urlsplit(url).hostname

        if hostname:
            add_domain(hostname)

    # Extract standalone domain references.
    for content in content_sources:
        if not content:
            continue

        decoded_content = unescape(content)

        for match in DOMAIN_PATTERN.findall(decoded_content):
            add_domain(match)

    return domains


IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])"
)


def extract_ipv4_addresses(parsed_email: dict) -> list:
    """
    Extract and validate IPv4 addresses from email content.

    No network connections or lookups are performed.
    """
    metadata = parsed_email.get("metadata", {})
    body = parsed_email.get("body", {})

    content_sources = [
        metadata.get("subject", ""),
        body.get("text", ""),
        body.get("html", ""),
    ]

    addresses = []

    for content in content_sources:
        if not content:
            continue

        decoded_content = unescape(content)

        candidates = IPV4_PATTERN.findall(decoded_content)

        for candidate in candidates:
            try:
                validated_ip = str(
                    ipaddress.IPv4Address(candidate)
                )
                addresses.append(validated_ip)

            except ipaddress.AddressValueError:
                continue

    return list(dict.fromkeys(addresses))


def extract_email_addresses(parsed_email: dict) -> list:
    """
    Extract email addresses from the subject and email body.

    Addresses are normalized to lowercase.
    No messages are sent or external systems contacted.
    """
    metadata = parsed_email.get("metadata", {})
    body = parsed_email.get("body", {})

    content_sources = [
        metadata.get("subject", ""),
        body.get("text", ""),
        body.get("html", ""),
    ]

    addresses = []

    for content in content_sources:
        if not content:
            continue

        decoded_content = unescape(content)

        matches = EMAIL_PATTERN.findall(decoded_content)

        addresses.extend(
            address.lower()
            for address in matches
        )

    return list(dict.fromkeys(addresses))


def extract_file_hashes(parsed_email: dict) -> list:
    """
    Extract MD5, SHA-1 and SHA-256 hash indicators
    from the subject and email body.
    """
    metadata = parsed_email.get("metadata", {})
    body = parsed_email.get("body", {})

    content_sources = [
        metadata.get("subject", ""),
        body.get("text", ""),
        body.get("html", ""),
    ]

    hashes = []

    for content in content_sources:
        if not content:
            continue

        for algorithm, pattern in HASH_PATTERNS.items():
            matches = pattern.findall(content)

            for match in matches:
                hashes.append({
                    "value": match.lower(),
                    "type": algorithm,
                })

    # Deduplicate by algorithm and hash value.
    unique_hashes = []
    seen = set()

    for item in hashes:
        key = (item["type"], item["value"])

        if key not in seen:
            seen.add(key)
            unique_hashes.append(item)

    return unique_hashes


EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])"
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    r"(?![\w-])",
    re.IGNORECASE,
)


HASH_PATTERNS = {
    "md5": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
    "sha1": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"),
    "sha256": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
}


def extract_iocs(parsed_email: dict) -> dict:
    """
    Extract all supported IOC types from a parsed email.

    Returns a structured collection of indicators.
    """
    return {
        "urls": extract_urls(parsed_email),
        "domains": extract_domains(parsed_email),
        "ipv4_addresses": extract_ipv4_addresses(parsed_email),
        "email_addresses": extract_email_addresses(parsed_email),
        "file_hashes": extract_file_hashes(parsed_email),
    }