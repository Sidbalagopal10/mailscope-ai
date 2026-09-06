from __future__ import annotations

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_security.contextual_decision import (
    contextual_email_decision,
)


def authenticated_message():
    return parse_email_authentication(
        [
            {
                "name": "From",
                "value": "Manager <manager@example.com>",
            },
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "spf=pass smtp.mailfrom=example.com; "
                    "dkim=pass header.d=example.com; "
                    "dmarc=pass header.from=example.com"
                ),
            },
        ]
    )


def test_authenticated_gift_card_secrecy_stays_high_risk():
    result = contextual_email_decision(
        subject="Urgent confidential request",
        body=(
            "Buy five gift cards immediately. "
            "Keep this confidential and send me the codes."
        ),
        authentication=authenticated_message(),
        known_sender=True,
        existing_thread=False,
        sender_domain_verified=True,
    )

    assert result["risk_score"] >= 72
    assert result["risk_level"] in {
        "high",
        "critical",
    }

    assert any(
        "business-email-compromise"
        in signal.lower()
        for signal in result[
            "suspicious_signals"
        ]
    )


def test_authenticated_normal_work_request_remains_low():
    result = contextual_email_decision(
        subject="Urgent report needed today",
        body=(
            "Please send the quarterly report before "
            "our 3 PM meeting."
        ),
        authentication=authenticated_message(),
        link_risk_score=0,
        attachment_risk_score=0,
        known_sender=True,
        existing_thread=True,
        sender_domain_verified=True,
    )

    assert result["risk_level"] == "low"
    assert result[
        "authenticated_normal_urgency"
    ]


def test_gift_card_without_authentication_is_high_risk():
    result = contextual_email_decision(
        subject="Urgent request",
        body=(
            "Purchase gift cards today and send me the codes."
        ),
        authentication=None,
        known_sender=False,
        existing_thread=False,
        sender_domain_verified=False,
    )

    assert result["risk_score"] >= 72
    assert result["risk_level"] in {
        "high",
        "critical",
    }


def test_financial_request_with_secrecy_is_high_risk():
    result = contextual_email_decision(
        subject="Confidential payment",
        body=(
            "Keep this confidential and complete the bank "
            "transfer today."
        ),
        authentication=authenticated_message(),
        known_sender=True,
        sender_domain_verified=True,
    )

    assert result["risk_score"] >= 68
    assert result["risk_level"] == "high"
