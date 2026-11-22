
import hashlib
import re
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime


MAX_EMAIL_SIZE = 10 * 1024 * 1024
MAX_MIME_PARTS = 200
MAX_ATTACHMENTS = 50


class EmailParsingError(ValueError):
    """Raised when an email cannot be safely ingested."""


def _decode_part(part) -> str:
    """Decode a MIME text part without executing or rendering it."""
    payload = part.get_payload(decode=True)

    if payload is None:
        content = part.get_content()
        return content if isinstance(content, str) else ""

    charset = part.get_content_charset() or "utf-8"

    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_addresses(message, header_name: str) -> list:
    """Extract structured addresses from an email header."""
    values = message.get_all(header_name, [])

    addresses = getaddresses([str(value) for value in values])

    return [
        {
            "name": name,
            "email": address,
        }
        for name, address in addresses
        if address
    ]


def _extract_body(message) -> dict:
    """Extract plain-text and HTML body content safely."""
    body = {
        "text": [],
        "html": [],
    }

    part_count = 0

    for part in message.walk():
        part_count += 1

        if part_count > MAX_MIME_PARTS:
            raise EmailParsingError(
                "Email exceeds the maximum MIME part limit."
            )

        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_filename():
            continue

        if part.get_content_maintype() != "text":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        content = _decode_part(part)

        if content_type == "text/plain":
            body["text"].append(content)
        else:
            body["html"].append(content)

    return {
        "text": "\n".join(body["text"]),
        "html": "\n".join(body["html"]),
    }


def _safe_filename(filename: str | None) -> str:
    """Create a safe display filename without trusting the supplied path."""
    if not filename:
        return "unnamed_attachment"

    # Treat both Windows and Unix path separators as untrusted.
    filename = str(filename).replace("\\", "/").split("/")[-1]

    # Remove control characters.
    filename = re.sub(r"[\x00-\x1f\x7f]", "", filename).strip()

    if filename in ("", ".", ".."):
        return "unnamed_attachment"

    return filename[:255]

def _extract_attachments(message) -> list:
    """Extract attachment metadata without saving attachment contents."""
    attachments = []
    part_count = 0

    for part in message.walk():
        part_count += 1

        if part_count > MAX_MIME_PARTS:
            raise EmailParsingError(
                "Email exceeds the maximum MIME part limit."
            )

        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()
        original_filename = part.get_filename()

        if disposition != "attachment" and not original_filename:
            continue

        if len(attachments) >= MAX_ATTACHMENTS:
            raise EmailParsingError(
                "Email exceeds the maximum attachment count."
            )

        attachment_bytes = part.get_payload(decode=True)
        decoded = isinstance(attachment_bytes, bytes)

        metadata = {
            "original_filename": str(original_filename)
            if original_filename else None,
            "safe_filename": _safe_filename(original_filename),
            "mime_type": part.get_content_type(),
            "content_disposition": disposition,
            "transfer_encoding": part.get("Content-Transfer-Encoding"),
            "size_bytes": len(attachment_bytes) if decoded else None,
            "sha256": (
                hashlib.sha256(attachment_bytes).hexdigest()
                if decoded else None
            ),
            "decode_status": "decoded" if decoded else "unavailable",
        }

        attachments.append(metadata)

    return attachments

def _parse_date(value) -> str | None:
    """Convert the message Date header to ISO 8601."""
    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(str(value))
        return parsed.isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def parse_eml(raw_email: bytes) -> dict:
    """
    Parse an EML message into structured investigation data.

    The original bytes are hashed before parsing.
    Attachments are not executed or extracted.
    """
    if not isinstance(raw_email, bytes):
        raise TypeError("Email input must be bytes.")

    if not raw_email:
        raise EmailParsingError("Email file is empty.")

    if len(raw_email) > MAX_EMAIL_SIZE:
        raise EmailParsingError(
            "Email exceeds the maximum allowed size of 10 MB."
        )

    original_hash = hashlib.sha256(raw_email).hexdigest()

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email)
    except Exception as exc:
        raise EmailParsingError(
            "Unable to parse the supplied email."
        ) from exc

    body = _extract_body(message)

    headers = [
        {
            "name": name,
            "value": str(value),
        }
        for name, value in message.items()
    ]

    return {
        "metadata": {
            "subject": str(message.get("Subject", "")),
            "from": _extract_addresses(message, "From"),
            "to": _extract_addresses(message, "To"),
            "cc": _extract_addresses(message, "Cc"),
            "reply_to": _extract_addresses(message, "Reply-To"),
            "return_path": str(message.get("Return-Path", "")),
            "message_id": str(message.get("Message-ID", "")),
            "date": _parse_date(message.get("Date")),
        },
        "headers": headers,
        "body": body,
        "attachments": _extract_attachments(message),
        "evidence": {
            "sha256": original_hash,
            "size_bytes": len(raw_email),
            "mime_type": message.get_content_type(),
            "is_multipart": message.is_multipart(),
            "ingested_at": datetime.now().astimezone().isoformat(),
        },
    }