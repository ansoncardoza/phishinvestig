
import re


AUTH_STATUSES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
}

AUTH_METHODS = {"spf", "dkim", "dmarc"}


def _extract_authentication_headers(headers: list) -> dict:
    """Collect authentication-related headers without discarding duplicates."""
    collected = {
        "authentication_results": [],
        "received_spf": [],
        "dkim_signature": [],
    }

    for header in headers:
        name = str(header.get("name", "")).strip().lower()
        value = str(header.get("value", "")).strip()

        if name == "authentication-results":
            collected["authentication_results"].append(value)
        elif name == "received-spf":
            collected["received_spf"].append(value)
        elif name == "dkim-signature":
            collected["dkim_signature"].append(value)

    return collected


def _extract_authserv_id(header_value: str) -> str | None:
    """Extract the Authentication-Results reporting server identifier."""
    first_section = header_value.split(";", 1)[0].strip()

    if not first_section:
        return None

    return first_section.split()[0].lower()


def _parse_authentication_results(
    values: list,
    trusted_authserv_ids: set | None = None,
) -> dict:
    """Extract authentication results and assess reporting server trust."""
    trusted_authserv_ids = {
        str(server).strip().lower()
        for server in (trusted_authserv_ids or set())
        if str(server).strip()
    }

    results = {
        "spf": [],
        "dkim": [],
        "dmarc": [],
    }

    pattern = re.compile(
        r"(?<![\w-])(spf|dkim|dmarc)\s*=\s*"
        r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        re.IGNORECASE,
    )

    for value in values:
        authserv_id = _extract_authserv_id(value)

        if authserv_id is None:
            trust_status = "unknown"
        elif authserv_id in trusted_authserv_ids:
            trust_status = "trusted"
        else:
            trust_status = "untrusted"

        for match in pattern.finditer(value):
            method = match.group(1).lower()
            status = match.group(2).lower()

            results[method].append({
                "status": status,
                "header": value,
                "authserv_id": authserv_id,
                "trust_status": trust_status,
                "verification_status": "not_performed",
            })

    return results


def _parse_received_spf(values: list) -> list:
    """Extract reported SPF statuses from Received-SPF headers."""
    results = []

    for value in values:
        match = re.match(
            r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            value,
            re.IGNORECASE,
        )

        if match:
            results.append({
                "status": match.group(1).lower(),
                "header": value,
                "authserv_id": None,
                "trust_status": "unknown",
                "verification_status": "not_performed",
            })

    return results

def _summarize_results(method_results: list) -> str:
    """Summarize results without hiding contradictory evidence."""
    if not method_results:
        return "not_evaluated"

    statuses = {
        item["status"]
        for item in method_results
    }

    if len(statuses) > 1:
        return "conflict"

    return next(iter(statuses))

def analyze_authentication(
    parsed_email: dict,
    trusted_authserv_ids: set | None = None,
) -> dict:
    """Analyze recorded SPF, DKIM and DMARC authentication evidence."""
    headers = parsed_email.get("headers", [])

    collected = _extract_authentication_headers(headers)

    reported = _parse_authentication_results(
    collected["authentication_results"],
    trusted_authserv_ids,
    )

    received_spf = _parse_received_spf(
        collected["received_spf"]
    )

    if not reported["spf"] and received_spf:
        reported["spf"] = received_spf

    authentication = {}

    for method in AUTH_METHODS:
        method_results = reported[method]

        authentication[method] = {
            "status": _summarize_results(method_results),
            "results": method_results,
            "evidence_available": bool(method_results),
        }

    return {
        "authentication": authentication,
        "evidence": {
            "authentication_results_headers": (
                collected["authentication_results"]
            ),
            "received_spf_headers": collected["received_spf"],
            "dkim_signature_count": len(
                collected["dkim_signature"]
            ),
            "dkim_signature_present": bool(
                collected["dkim_signature"]
            ),
        },
        "summary": {
            "spf": authentication["spf"]["status"],
            "dkim": authentication["dkim"]["status"],
            "dmarc": authentication["dmarc"]["status"],
        },
        "verification_note": (
        "Authentication results are reported claims, not independently "
        "verified results. Reporting server trust is assessed only against "
        "the configured trusted_authserv_ids. Received-SPF server trust "
        "is not established by this analyzer."
        ),
    }
