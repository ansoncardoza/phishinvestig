
from email.utils import parseaddr


def _extract_domain(address: str) -> str | None:
    """Extract a normalized domain from an email address."""
    if not address:
        return None

    _, parsed_address = parseaddr(str(address))
    parsed_address = parsed_address.strip().lower()

    if "@" not in parsed_address:
        return None

    domain = parsed_address.rsplit("@", 1)[1].strip()

    if not domain or "." not in domain:
        return None

    if any(char.isspace() for char in domain):
        return None

    return domain.rstrip(".")


def _get_first_email(metadata: dict, field: str) -> str | None:
    """Get the first email address from a parsed metadata field."""
    addresses = metadata.get(field, [])

    if not addresses:
        return None

    return addresses[0].get("email")


def _extract_received_headers(headers: list) -> list:
    """Extract Received headers in their original stored order."""
    return [
        header.get("value", "")
        for header in headers
        if header.get("name", "").lower() == "received"
    ]


def analyze_headers(parsed_email: dict) -> dict:
    """
    Analyze email headers for sender identity and routing indicators.

    This module produces investigation findings, not a definitive
    phishing verdict.
    """
    metadata = parsed_email.get("metadata", {})
    headers = parsed_email.get("headers", [])

    findings = []

    from_address = _get_first_email(metadata, "from")
    reply_to_address = _get_first_email(metadata, "reply_to")

    return_path = metadata.get("return_path", "")
    return_path_address = parseaddr(str(return_path))[1] or None

    from_domain = _extract_domain(from_address)
    reply_to_domain = _extract_domain(reply_to_address)
    return_path_domain = _extract_domain(return_path_address)

    if not from_address:
        findings.append({
            "rule_id": "HDR001",
            "severity": "medium",
            "title": "Missing sender address",
            "description": (
                "The email does not contain a usable From address."
            ),
            "evidence": None,
        })

    if reply_to_address and from_domain and reply_to_domain:
        if from_domain != reply_to_domain:
            findings.append({
                "rule_id": "HDR002",
                "severity": "medium",
                "title": "From and Reply-To domain mismatch",
                "description": (
                    "The Reply-To domain differs from the sender domain. "
                    "Investigate whether replies are being redirected."
                ),
                "evidence": {
                    "from_address": from_address,
                    "reply_to_address": reply_to_address,
                    "from_domain": from_domain,
                    "reply_to_domain": reply_to_domain,
                },
            })

    if return_path_domain and from_domain:
        if return_path_domain != from_domain:
            findings.append({
                "rule_id": "HDR003",
                "severity": "low",
                "title": "From and Return-Path domain mismatch",
                "description": (
                    "The Return-Path domain differs from the From domain. "
                    "This can be legitimate, but warrants investigation."
                ),
                "evidence": {
                    "from_domain": from_domain,
                    "return_path_domain": return_path_domain,
                },
            })

    received_headers = _extract_received_headers(headers)

    if not received_headers:
        findings.append({
            "rule_id": "HDR004",
            "severity": "low",
            "title": "No Received headers found",
            "description": (
                "No Received headers were available for routing analysis."
            ),
            "evidence": None,
        })

    return {
        "sender": {
            "from_address": from_address,
            "from_domain": from_domain,
            "reply_to_address": reply_to_address,
            "reply_to_domain": reply_to_domain,
            "return_path_address": return_path_address,
            "return_path_domain": return_path_domain,
        },
        "routing": {
            "received_header_count": len(received_headers),
            "received_headers": received_headers,
        },
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "high": sum(
                item["severity"] == "high" for item in findings
            ),
            "medium": sum(
                item["severity"] == "medium" for item in findings
            ),
            "low": sum(
                item["severity"] == "low" for item in findings
            ),
        },
    }
