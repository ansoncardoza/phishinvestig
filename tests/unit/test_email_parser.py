
import hashlib
from email.message import EmailMessage
from email import policy

import pytest

from src.ingestion.email_parser import (
    MAX_EMAIL_SIZE,
    MAX_ATTACHMENTS,
    MAX_MIME_PARTS,
    EmailParsingError,
    parse_eml,
)


def create_email(
    subject="Test Email",
    sender="sender@example.com",
    recipient="analyst@example.com",
    date="Sat, 21 Nov 2026 10:30:00 +0000",
):
    message = EmailMessage(policy=policy.default)
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject

    if date is not None:
        message["Date"] = date

    message["Message-ID"] = "<test-001@example.com>"
    message.set_content("This is a synthetic test email.")

    return message.as_bytes()


def create_multipart_email():
    message = EmailMessage(policy=policy.default)
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "Multipart Test"
    message["Date"] = "Sat, 21 Nov 2026 10:30:00 +0000"

    message.set_content("Plain text email body.")
    message.add_alternative(
        "<html><body><p>HTML email body.</p></body></html>",
        subtype="html",
    )

    message.add_attachment(
        b"Synthetic attachment content",
        maintype="application",
        subtype="octet-stream",
        filename="sample.txt",
    )

    return message.as_bytes()


def test_parse_basic_email():
    raw_email = create_email()

    result = parse_eml(raw_email)

    assert result["metadata"]["subject"] == "Test Email"
    assert result["metadata"]["from"][0]["email"] == "sender@example.com"
    assert result["metadata"]["to"][0]["email"] == "analyst@example.com"
    assert result["body"]["text"].strip() == "This is a synthetic test email."


def test_preserves_original_sha256():
    raw_email = create_email()

    result = parse_eml(raw_email)

    expected_hash = hashlib.sha256(raw_email).hexdigest()

    assert result["evidence"]["sha256"] == expected_hash
    assert result["evidence"]["size_bytes"] == len(raw_email)


def test_extracts_multipart_body_without_attachment_content():
    raw_email = create_multipart_email()

    result = parse_eml(raw_email)

    assert "Plain text email body." in result["body"]["text"]
    assert "HTML email body." in result["body"]["html"]
    assert "Synthetic attachment content" not in result["body"]["text"]
    assert "Synthetic attachment content" not in result["body"]["html"]


def test_extracts_message_id():
    result = parse_eml(create_email())

    assert (
        result["metadata"]["message_id"]
        == "<test-001@example.com>"
    )


def test_preserves_repeated_headers():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: analyst@example.com\r\n"
        b"Subject: Header Test\r\n"
        b"Received: first.example\r\n"
        b"Received: second.example\r\n"
        b"\r\n"
        b"Test body.\r\n"
    )

    result = parse_eml(raw_email)

    received_headers = [
        header["value"]
        for header in result["headers"]
        if header["name"].lower() == "received"
    ]

    assert received_headers == [
        "first.example",
        "second.example",
    ]


def test_invalid_date_returns_none():
    raw_email = create_email(date="not-a-valid-date")

    result = parse_eml(raw_email)

    assert result["metadata"]["date"] is None


def test_missing_date_returns_none():
    raw_email = create_email(date=None)

    result = parse_eml(raw_email)

    assert result["metadata"]["date"] is None


def test_empty_email_is_rejected():
    with pytest.raises(EmailParsingError):
        parse_eml(b"")


def test_oversized_email_is_rejected():
    raw_email = b"A" * (MAX_EMAIL_SIZE + 1)

    with pytest.raises(EmailParsingError):
        parse_eml(raw_email)


def test_non_bytes_input_is_rejected():
    with pytest.raises(TypeError):
        parse_eml("This is not bytes")


def test_evidence_size_and_mime_metadata():
    raw_email = create_email()

    result = parse_eml(raw_email)

    assert result["evidence"]["mime_type"] == "text/plain"
    assert result["evidence"]["is_multipart"] is False
    assert result["evidence"]["ingested_at"]


def test_extracts_attachment_metadata():
    result = parse_eml(create_multipart_email())

    assert len(result["attachments"]) == 1

    attachment = result["attachments"][0]

    assert attachment["safe_filename"] == "sample.txt"
    assert attachment["mime_type"] == "application/octet-stream"
    assert attachment["size_bytes"] == len(
        b"Synthetic attachment content"
    )
    assert attachment["sha256"] == hashlib.sha256(
        b"Synthetic attachment content"
    ).hexdigest()
    assert attachment["decode_status"] == "decoded"


def test_attachment_content_is_not_saved_in_body():
    result = parse_eml(create_multipart_email())

    assert "attachments" in result
    assert "Synthetic attachment content" not in result["body"]["text"]
    assert "Synthetic attachment content" not in result["body"]["html"]


def test_sanitizes_attachment_filename():
    from src.ingestion.email_parser import _safe_filename

    assert _safe_filename("../../malicious.exe") == "malicious.exe"
    assert _safe_filename(r"C:\temp\invoice.pdf") == "invoice.pdf"
    assert _safe_filename("..") == "unnamed_attachment"
    assert _safe_filename(None) == "unnamed_attachment"


def test_email_without_attachments_returns_empty_list():
    result = parse_eml(create_email())

    assert result["attachments"] == []

def test_rejects_excessive_attachments():
    message = EmailMessage(policy=policy.default)
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "Attachment Limit Test"
    message.set_content("Testing attachment limits.")

    for index in range(MAX_ATTACHMENTS + 1):
        message.add_attachment(
            f"Attachment {index}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"attachment_{index}.bin",
        )

    with pytest.raises(
        EmailParsingError,
        match="maximum attachment count",
    ):
        parse_eml(message.as_bytes())


def test_rejects_excessive_mime_parts():
    message = EmailMessage(policy=policy.default)
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "MIME Part Limit Test"
    message.set_content("Testing MIME limits.")

    for index in range(MAX_MIME_PARTS):
        message.add_attachment(
            f"Part {index}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"part_{index}.bin",
        )

    with pytest.raises(
        EmailParsingError,
        match="maximum MIME part limit",
    ):
        parse_eml(message.as_bytes())


def test_extracts_multiple_attachment_hashes():
    message = EmailMessage(policy=policy.default)
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "Multiple Attachments"
    message.set_content("Multiple attachment test.")

    contents = [
        b"First synthetic attachment",
        b"Second synthetic attachment",
    ]

    for index, content in enumerate(contents):
        message.add_attachment(
            content,
            maintype="application",
            subtype="octet-stream",
            filename=f"file_{index}.bin",
        )

    result = parse_eml(message.as_bytes())

    assert len(result["attachments"]) == 2

    for attachment, content in zip(result["attachments"], contents):
        assert attachment["sha256"] == hashlib.sha256(
            content
        ).hexdigest()
        assert attachment["size_bytes"] == len(content)