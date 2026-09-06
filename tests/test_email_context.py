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


def authentication_headers(
    *,
    spf: str,
    dkim: str,
    dmarc: str,
):
    return [
        {
            "name": "From",
            "value": (
                "Professor "
                "<professor@example.edu>"
            ),
        },
        {
            "name": "Authentication-Results",
            "value": (
                "mx.google.com; "
                f"spf={spf} smtp.mailfrom=example.edu; "
                f"dkim={dkim} header.d=example.edu; "
                f"dmarc={dmarc} header.from=example.edu"
            ),
        },
    ]


def test_urgent_assignment_is_normal_context():
    result = analyze_message_context(
        subject=(
            "Urgent: Assignment due tonight"
        ),
        body=(
            "Please submit Assignment 3 through "
            "Blackboard by 11:59 PM today."
        ),
    )

    assert result[
        "urgency_consistent_with_intent"
    ]

    assert (
        "academic_deadline"
        in result[
            "intent"
        ][
            "all_intents"
        ]
    )


def test_authenticated_professor_deadline_is_low_risk():
    authentication = (
        parse_email_authentication(
            authentication_headers(
                spf="pass",
                dkim="pass",
                dmarc="pass",
            )
        )
    )

    result = contextual_email_decision(
        subject=(
            "Urgent: Assignment due tonight"
        ),
        body=(
            "Please submit Assignment 3 through "
            "Blackboard by 11:59 PM."
        ),
        authentication=authentication,
        link_risk_score=5,
        known_sender=True,
        existing_thread=True,
        sender_domain_verified=True,
    )

    assert result[
        "authenticated_normal_urgency"
    ]

    assert (
        result[
            "risk_level"
        ]
        == "low"
    )

    assert (
        result[
            "classification"
        ]
        == "likely_legitimate"
    )


def test_authenticated_manager_meeting_is_low_risk():
    authentication = (
        parse_email_authentication(
            authentication_headers(
                spf="pass",
                dkim="pass",
                dmarc="pass",
            )
        )
    )

    result = contextual_email_decision(
        subject=(
            "Last-minute meeting at 3 PM"
        ),
        body=(
            "Please join our Teams meeting today "
            "to review the project report."
        ),
        authentication=authentication,
        link_risk_score=5,
        known_sender=True,
        existing_thread=True,
        sender_domain_verified=True,
    )

    assert (
        result[
            "risk_level"
        ]
        == "low"
    )


def test_spoofed_urgent_login_request_is_high_risk():
    authentication = (
        parse_email_authentication(
            authentication_headers(
                spf="fail",
                dkim="fail",
                dmarc="fail",
            )
        )
    )

    result = contextual_email_decision(
        subject=(
            "URGENT: Verify your university account"
        ),
        body=(
            "Your account will be suspended today. "
            "Log in immediately and verify your password."
        ),
        authentication=authentication,
        link_risk_score=75,
        known_sender=False,
        existing_thread=False,
        sender_domain_verified=False,
    )

    assert result[
        "risk_score"
    ] >= 75

    assert result[
        "classification"
    ] == "likely_phishing"


def test_gift_card_request_is_high_risk():
    authentication = (
        parse_email_authentication(
            authentication_headers(
                spf="pass",
                dkim="pass",
                dmarc="pass",
            )
        )
    )

    result = contextual_email_decision(
        subject=(
            "Urgent confidential request"
        ),
        body=(
            "Buy five gift cards immediately. "
            "Keep this confidential and send me the codes."
        ),
        authentication=authentication,
        known_sender=True,
        existing_thread=False,
        sender_domain_verified=True,
    )

    assert (
        result[
            "risk_level"
        ]
        in {
            "high",
            "critical",
        }
    )

    assert (
        "gift_card_request"
        in result[
            "message_context"
        ][
            "intent"
        ][
            "all_intents"
        ]
    )


def test_urgency_alone_does_not_add_risk():
    result = contextual_email_decision(
        subject="Urgent reminder",
        body=(
            "The office closes early today."
        ),
        authentication=None,
        known_sender=False,
        existing_thread=False,
        sender_domain_verified=False,
    )

    assert result[
        "risk_score"
    ] < 35
