from __future__ import annotations

from typing import Any

from app.email_authentication.risk import (
    authentication_risk_evidence,
)
from app.email_context.intent_engine import (
    analyze_message_context,
)


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            value,
            maximum,
        ),
    )


def contextual_email_decision(
    *,
    subject: str | None,
    body: str | None,
    authentication: dict[
        str,
        Any,
    ] | None,
    link_risk_score: float = 0.0,
    attachment_risk_score: float = 0.0,
    known_sender: bool = False,
    existing_thread: bool = False,
    sender_domain_verified: bool = False,
) -> dict[str, Any]:
    """
    Combine intent, urgency, authentication, sender history,
    thread context, and existing URL/attachment evidence.

    Urgency alone contributes no phishing risk.
    """
    context = analyze_message_context(
        subject=subject,
        body=body,
    )

    auth_evidence = (
        authentication_risk_evidence(
            authentication
        )
    )

    reasons: list[str] = []
    positive_signals: list[str] = []
    suspicious_signals: list[str] = []

    score = 0.0

    link_risk = clamp(
        float(
            link_risk_score
            or 0
        )
    )

    attachment_risk = clamp(
        float(
            attachment_risk_score
            or 0
        )
    )

    score += link_risk * 0.55
    score += attachment_risk * 0.45

    auth_adjustment = float(
        auth_evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    score += auth_adjustment

    urgency = context[
        "urgency"
    ]

    intent = context[
        "intent"
    ]

    high_risk_intents = set(
        intent.get(
            "high_risk_intents",
            [],
        )
    )

    normal_urgency_intents = set(
        intent.get(
            "normal_urgency_intents",
            [],
        )
    )

    if urgency[
        "detected"
    ]:
        reasons.append(
            "Urgency language was detected, but urgency "
            "alone did not add phishing risk."
        )

    if context[
        "urgency_consistent_with_intent"
    ]:
        positive_signals.append(
            "Urgency is consistent with an academic, meeting, "
            "or ordinary work deadline."
        )

    if context[
        "urgency_combined_with_high_risk_intent"
    ]:
        score += 12.0

        suspicious_signals.append(
            "Urgency accompanies a credential, financial, "
            "gift-card, or account-security request."
        )

    if urgency[
        "pressure_language"
    ]:
        score += 8.0

        suspicious_signals.append(
            "The message uses coercive pressure language."
        )

    if urgency[
        "secrecy_language"
    ]:
        score += 18.0

        suspicious_signals.append(
            "The message requests secrecy or discourages verification."
        )

    if "gift_card_request" in high_risk_intents:
        score += 30.0

        suspicious_signals.append(
            "Gift-card requests are strongly associated with "
            "business-email-compromise scams."
        )

    if "financial_request" in high_risk_intents:
        score += 18.0

        suspicious_signals.append(
            "The message requests a financial action."
        )

    if "credential_request" in high_risk_intents:
        score += 14.0

        suspicious_signals.append(
            "The message requests authentication or credentials."
        )

    # High-confidence business-email-compromise patterns need
    # explicit score floors. Authentication can pass when a real
    # mailbox is compromised, so it must not neutralize these
    # combinations.
    gift_card_with_social_pressure = bool(
        "gift_card_request" in high_risk_intents
        and (
            urgency["detected"]
            or urgency["pressure_language"]
            or urgency["secrecy_language"]
        )
    )

    financial_request_with_secrecy = bool(
        "financial_request" in high_risk_intents
        and urgency["secrecy_language"]
    )

    credential_request_with_coercion = bool(
        "credential_request" in high_risk_intents
        and (
            urgency["pressure_language"]
            or urgency["secrecy_language"]
        )
    )

    if gift_card_with_social_pressure:
        score = max(
            score,
            72.0,
        )

        suspicious_signals.append(
            "A gift-card request combined with urgency, pressure, "
            "or secrecy is a strong business-email-compromise pattern."
        )

        reasons.append(
            "Authentication success did not lower this verdict because "
            "a legitimate mailbox can be compromised."
        )

    if financial_request_with_secrecy:
        score = max(
            score,
            68.0,
        )

        suspicious_signals.append(
            "A financial request combined with secrecy requires "
            "independent verification."
        )

    if credential_request_with_coercion:
        score = max(
            score,
            65.0,
        )

        suspicious_signals.append(
            "A credential request combined with coercive language "
            "is high risk."
        )

    # BEGIN EXTENDED BEC SCORE FLOORS
    #
    # Passing authentication and sender familiarity cannot make
    # prepaid-card, secret-code, or sensitive payment-change
    # requests trustworthy. A real mailbox may be compromised.

    prepaid_card_bec = bool(
        "gift_card_request" in high_risk_intents
        and (
            urgency["detected"]
            or urgency["pressure_language"]
            or urgency["secrecy_language"]
        )
    )

    financial_change_with_pressure = bool(
        "financial_request" in high_risk_intents
        and (
            urgency["pressure_language"]
            or urgency["secrecy_language"]
        )
    )

    credential_financial_combination = bool(
        "credential_request" in high_risk_intents
        and "financial_request" in high_risk_intents
    )

    if prepaid_card_bec:
        score = max(
            score,
            76.0,
        )

        suspicious_signals.append(
            "A prepaid-card or redemption-code request combined "
            "with urgency, pressure, or secrecy is a strong "
            "business-email-compromise pattern."
        )

        reasons.append(
            "Sender authentication and familiarity did not suppress "
            "the verdict because a legitimate mailbox can be compromised."
        )

    if financial_change_with_pressure:
        score = max(
            score,
            72.0,
        )

        suspicious_signals.append(
            "A payment, bank-account, beneficiary, or refund request "
            "combined with pressure or secrecy requires independent "
            "verification."
        )

    if credential_financial_combination:
        score = max(
            score,
            78.0,
        )

        suspicious_signals.append(
            "The message combines sensitive financial information "
            "with an authentication or credential request."
        )

    # END EXTENDED BEC SCORE FLOORS

    if known_sender:
        positive_signals.append(
            "The sender has been observed previously."
        )

        if not high_risk_intents:
            score -= 5.0

    if existing_thread:
        positive_signals.append(
            "The message belongs to an existing conversation thread."
        )

        if not high_risk_intents:
            score -= 5.0

    if sender_domain_verified:
        positive_signals.append(
            "The sender domain is associated with a verified organization."
        )

        if (
            auth_evidence.get(
                "verdict"
            )
            == "authenticated"
            and not high_risk_intents
        ):
            score -= 5.0

    authenticated_normal_urgency = bool(
        auth_evidence.get(
            "verdict"
        )
        == "authenticated"
        and normal_urgency_intents
        and not high_risk_intents
        and not urgency[
            "secrecy_language"
        ]
        and link_risk < 35
        and attachment_risk < 35
    )

    if authenticated_normal_urgency:
        score = min(
            score,
            15.0,
        )

        positive_signals.append(
            "Authenticated normal business or academic urgency "
            "was prevented from becoming a phishing verdict."
        )

    triple_auth_failure = (
        "SPF, DKIM, and DMARC all failed"
        in auth_evidence.get(
            "strong_signals",
            [],
        )
    )

    if triple_auth_failure and (
        high_risk_intents
        or link_risk >= 35
    ):
        score = max(
            score,
            75.0,
        )

        suspicious_signals.append(
            "Authentication failures corroborate suspicious "
            "message content or links."
        )

    score = round(
        clamp(
            score
        ),
        2,
    )

    if score >= 80:
        risk_level = "critical"
        classification = (
            "likely_phishing"
        )
        recommendation = (
            "Do not follow the requested action. Verify the "
            "sender through a separately obtained contact method."
        )

    elif score >= 60:
        risk_level = "high"
        classification = (
            "high_risk"
        )
        recommendation = (
            "Do not enter credentials, transfer money, or open "
            "attachments until the request is independently verified."
        )

    elif score >= 35:
        risk_level = "moderate"
        classification = (
            "needs_review"
        )
        recommendation = (
            "Review the sender, links, attachments, and request "
            "context before acting."
        )

    else:
        risk_level = "low"
        classification = (
            "likely_legitimate"
        )
        recommendation = (
            "No strong phishing evidence was found. Normal caution "
            "still applies."
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "classification": (
            classification
        ),
        "recommendation": (
            recommendation
        ),
        "authenticated_normal_urgency": (
            authenticated_normal_urgency
        ),
        "message_context": context,
        "authentication_evidence": (
            auth_evidence
        ),
        "link_risk_score": (
            link_risk
        ),
        "attachment_risk_score": (
            attachment_risk
        ),
        "known_sender": known_sender,
        "existing_thread": (
            existing_thread
        ),
        "sender_domain_verified": (
            sender_domain_verified
        ),
        "positive_signals": (
            positive_signals
        ),
        "suspicious_signals": (
            suspicious_signals
        ),
        "reasons": reasons,
        "important_limitations": [
            (
                "A known sender account can be compromised."
            ),
            (
                "An existing thread can be hijacked."
            ),
            (
                "Authentication verifies message-handling identity, "
                "not whether a request is appropriate."
            ),
            (
                "Urgent credential, payment, gift-card, or secrecy "
                "requests should still be independently verified."
            ),
        ],
    }
