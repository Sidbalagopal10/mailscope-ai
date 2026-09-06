from __future__ import annotations

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_context.intent_engine import (
    analyze_message_context,
)
from app.email_security.contextual_decision import (
    contextual_email_decision,
)


def authenticated_manager():
    return parse_email_authentication(
        [
            {
                "name": "From",
                "value": (
                    "Manager <manager@example.com>"
                ),
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


def failed_authentication():
    return parse_email_authentication(
        [
            {
                "name": "From",
                "value": (
                    "Refund Office "
                    "<refund@refund-example.test>"
                ),
            },
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "spf=fail smtp.mailfrom=attacker.test; "
                    "dkim=fail header.d=attacker.test; "
                    "dmarc=fail header.from=refund-example.test"
                ),
            },
        ]
    )


def test_prepaid_card_photograph_request_is_bec():
    context = analyze_message_context(
        subject="Need this handled now",
        body=(
            "Do not call me. Purchase prepaid cards "
            "immediately and send photographs of the codes."
        ),
    )

    assert (
        "gift_card_request"
        in context[
            "intent"
        ][
            "all_intents"
        ]
    )

    assert context[
        "urgency"
    ][
        "secrecy_language"
    ]


def test_authenticated_prepaid_card_bec_is_high():
    result = contextual_email_decision(
        subject="Need this handled now",
        body=(
            "Do not call me. Purchase prepaid cards "
            "immediately and send photographs of the codes."
        ),
        authentication=authenticated_manager(),
        known_sender=True,
        existing_thread=False,
        sender_domain_verified=True,
    )

    assert result[
        "risk_score"
    ] >= 76

    assert result[
        "risk_level"
    ] in {
        "high",
        "critical",
    }


def test_bank_details_and_password_request_is_high():
    result = contextual_email_decision(
        subject="Tax refund pending",
        body=(
            "Confirm your bank details and password "
            "immediately to receive your refund."
        ),
        authentication=failed_authentication(),
        known_sender=False,
        existing_thread=False,
        sender_domain_verified=False,
    )

    assert result[
        "risk_score"
    ] >= 78

    assert result[
        "risk_level"
    ] in {
        "high",
        "critical",
    }


def test_normal_authenticated_invoice_remains_low():
    result = contextual_email_decision(
        subject="Invoice 4832 for July services",
        body=(
            "Attached is the July invoice under our existing "
            "contract. Payment terms remain net 30."
        ),
        authentication=authenticated_manager(),
        known_sender=True,
        existing_thread=True,
        sender_domain_verified=True,
    )

    assert result[
        "risk_level"
    ] == "low"


def test_normal_salary_notice_is_not_automatically_phishing():
    result = contextual_email_decision(
        subject="Payroll processing schedule",
        body=(
            "Payroll will be processed Friday according "
            "to the normal company schedule."
        ),
        authentication=authenticated_manager(),
        known_sender=True,
        existing_thread=True,
        sender_domain_verified=True,
    )

    assert result[
        "risk_level"
    ] == "low"
