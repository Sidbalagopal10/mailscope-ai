from __future__ import annotations

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_authentication.risk import (
    authentication_risk_evidence,
)


def test_legitimate_authenticated_message():
    headers = [
        {
            "name": "From",
            "value": (
                "Professor Example "
                "<professor@example.edu>"
            ),
        },
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com; "
                "spf=pass smtp.mailfrom=example.edu; "
                "dkim=pass header.d=example.edu; "
                "dmarc=pass header.from=example.edu"
            ),
        },
    ]

    result = parse_email_authentication(
        headers
    )

    evidence = (
        authentication_risk_evidence(
            result
        )
    )

    assert result["from_domain"] == "example.edu"
    assert result["spf"]["result"] == "pass"
    assert result["dkim"]["result"] == "pass"
    assert result["dmarc"]["result"] == "pass"
    assert evidence["verdict"] == "authenticated"
    assert evidence["risk_adjustment"] < 0


def test_spoofed_message_multiple_failures():
    headers = [
        {
            "name": "From",
            "value": (
                "Manager "
                "<manager@example.com>"
            ),
        },
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com; "
                "spf=fail smtp.mailfrom=attacker.test; "
                "dkim=fail header.d=attacker.test; "
                "dmarc=fail header.from=example.com"
            ),
        },
    ]

    result = parse_email_authentication(
        headers
    )

    evidence = (
        authentication_risk_evidence(
            result
        )
    )

    assert evidence[
        "verdict"
    ] == "authentication_failed"

    assert evidence[
        "risk_adjustment"
    ] >= 38

    assert evidence[
        "strong_signals"
    ]


def test_forwarded_email_spf_failure_not_automatically_phishing():
    headers = [
        {
            "name": "From",
            "value": "Professor <professor@example.edu>",
        },
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com; "
                "spf=fail smtp.mailfrom=forwarder.example; "
                "dkim=pass header.d=example.edu; "
                "dmarc=pass header.from=example.edu; "
                "arc=pass"
            ),
        },
    ]

    authentication = (
        parse_email_authentication(
            headers
        )
    )

    evidence = (
        authentication_risk_evidence(
            authentication
        )
    )

    assert evidence["spf"] == "fail"
    assert evidence["dkim"] == "pass"
    assert evidence["dmarc"] == "pass"
    assert evidence["verdict"] == "authenticated"
    assert evidence["risk_adjustment"] <= 0


def test_missing_authentication_is_neutral():
    authentication = (
        parse_email_authentication(
            [
                {
                    "name": "From",
                    "value": "Person <person@example.org>",
                }
            ]
        )
    )

    evidence = (
        authentication_risk_evidence(
            authentication
        )
    )

    assert not evidence["available"]
    assert evidence["risk_adjustment"] == 0


def test_raw_header_string_supported():
    raw_headers = """From: Professor <professor@example.edu>
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.edu;
 dkim=pass header.d=example.edu; dmarc=pass header.from=example.edu
"""

    result = parse_email_authentication(
        raw_headers
    )

    assert result["dmarc"]["result"] == "pass"
