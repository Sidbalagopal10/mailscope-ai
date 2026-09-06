from __future__ import annotations

from typing import Any

from app.email_security.combined_analyzer import (
    analyze_gmail_message as analyze_content_and_urls,
)
from app.email_security.header_analyzer import (
    analyze_email_headers,
)


def score_to_risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    if score >= 20:
        return "GUARDED"

    return "LOW"


def _analyze_gmail_message_base(
    message: dict[str, Any],
) -> dict[str, Any]:
    """
    Produce a full Gmail risk assessment using:

    - email-content social-engineering analysis;
    - hybrid URL machine-learning analysis;
    - SPF, DKIM, DMARC, and sender-alignment analysis.
    """
    base_result = analyze_content_and_urls(
        message
    )

    payload = message.get(
        "payload",
        {},
    )

    headers = payload.get(
        "headers",
        [],
    )

    header_result = analyze_email_headers(
        headers
    )

    content_score = float(
        base_result.get(
            "content_score",
            0,
        )
        or 0
    )

    highest_url_score = float(
        base_result.get(
            "highest_url_score",
            0,
        )
        or 0
    )

    header_score = float(
        header_result.get(
            "header_score",
            0,
        )
        or 0
    )

    link_count = int(
        base_result.get(
            "link_count",
            0,
        )
        or 0
    )

    if link_count:
        final_score = (
            content_score * 0.30
            + highest_url_score * 0.50
            + header_score * 0.20
        )
    else:
        final_score = (
            content_score * 0.60
            + header_score * 0.40
        )

    reasons = list(
        base_result.get(
            "reasons",
            [],
        )
    )

    for reason in header_result.get(
        "reasons",
        [],
    ):
        if reason not in reasons:
            reasons.append(
                reason
            )

    authentication_failed = any(
        header_result.get(
            mechanism
        )
        not in {
            "pass",
            None,
        }
        for mechanism in (
            "spf",
            "dkim",
            "dmarc",
        )
    )

    sender_mismatch = bool(
        header_result.get(
            "reply_to_mismatch"
        )
        or header_result.get(
            "return_path_mismatch"
        )
    )

    suspicious_content = (
        content_score >= 40
    )

    suspicious_url = (
        highest_url_score >= 40
    )

    suspicious_headers = (
        header_score >= 40
    )

    if (
        suspicious_content
        and suspicious_url
    ):
        final_score += 6

        reasons.append(
            "Suspicious language and suspicious URLs "
            "appear together in the message."
        )

    if (
        suspicious_url
        and authentication_failed
    ):
        final_score += 6

        reasons.append(
            "A suspicious URL appears in a message "
            "with email-authentication problems."
        )

    if (
        sender_mismatch
        and suspicious_content
    ):
        final_score += 5

        reasons.append(
            "Sender-domain misalignment appears together "
            "with suspicious message language."
        )

    if (
        suspicious_headers
        and suspicious_content
        and suspicious_url
    ):
        final_score += 5

        reasons.append(
            "Content, URL, and email-header risk signals "
            "are all present in the same message."
        )

    final_score = round(
        min(
            final_score,
            100,
        ),
        2,
    )

    risk_level = score_to_risk_level(
        final_score
    )

    if final_score >= 80:
        recommendation = (
            "Do not interact with this message. Do not click links, "
            "open attachments, reply, provide credentials, or send money. "
            "Report it as phishing and verify the sender independently."
        )

    elif final_score >= 60:
        recommendation = (
            "Treat this message as likely phishing. Avoid all links "
            "and attachments until the sender is independently verified."
        )

    elif final_score >= 40:
        recommendation = (
            "Use caution. Verify the sender, domain, links, and request "
            "through a trusted communication channel."
        )

    elif final_score >= 20:
        recommendation = (
            "Some risk indicators were detected. Review the message "
            "carefully before taking action."
        )

    else:
        recommendation = (
            "No strong combined phishing indicators were detected, "
            "but normal email-security precautions still apply."
        )

    result = dict(
        base_result
    )

    result.update(
        {
            "combined_score": final_score,
            "full_email_score": final_score,
            "risk_level": risk_level,
            "is_suspicious": (
                final_score >= 40
            ),
            "is_phishing": (
                final_score >= 60
            ),
            "recommendation": (
                recommendation
            ),
            "reasons": reasons,
            "header_score": round(
                header_score,
                2,
            ),
            "header_analysis": (
                header_result
            ),
            "authentication_summary": {
                "spf": header_result.get(
                    "spf"
                ),
                "dkim": header_result.get(
                    "dkim"
                ),
                "dmarc": header_result.get(
                    "dmarc"
                ),
                "all_authentication_passed": (
                    header_result.get(
                        "all_authentication_passed",
                        False,
                    )
                ),
                "reply_to_mismatch": (
                    header_result.get(
                        "reply_to_mismatch",
                        False,
                    )
                ),
                "return_path_mismatch": (
                    header_result.get(
                        "return_path_mismatch",
                        False,
                    )
                ),
            },
            "score_components": {
                "content_score": round(
                    content_score,
                    2,
                ),
                "highest_url_score": round(
                    highest_url_score,
                    2,
                ),
                "header_score": round(
                    header_score,
                    2,
                ),
                "content_weight": (
                    0.30
                    if link_count
                    else 0.60
                ),
                "url_weight": (
                    0.50
                    if link_count
                    else 0.0
                ),
                "header_weight": (
                    0.20
                    if link_count
                    else 0.40
                ),
            },
            "analysis_version": (
                "full-email-risk-v1"
            ),
        }
    )

    return result


def analyze_gmail_message(
    message: dict[str, Any],
) -> dict[str, Any]:
    from app.trust.trust_evaluator import (
        evaluate_domain_trust,
    )

    result = _analyze_gmail_message_base(
        message
    )

    trust_result = evaluate_domain_trust(
        result
    )

    original_score = float(
        result.get(
            "combined_score",
            result.get(
                "full_email_score",
                0,
            ),
        )
        or 0
    )

    adjustment = float(
        trust_result.get(
            "score_adjustment",
            0,
        )
        or 0
    )

    adjusted_score = round(
        min(
            max(
                original_score
                + adjustment,
                0,
            ),
            100,
        ),
        2,
    )

    if adjusted_score >= 80:
        level = "CRITICAL"
    elif adjusted_score >= 60:
        level = "HIGH"
    elif adjusted_score >= 40:
        level = "MODERATE"
    elif adjusted_score >= 20:
        level = "GUARDED"
    else:
        level = "LOW"

    reasons = list(
        result.get(
            "reasons",
            [],
        )
    )

    for reason in trust_result.get(
        "reasons",
        [],
    ):
        if reason not in reasons:
            reasons.append(
                reason
            )

    result.update(
        {
            "pre_trust_score": original_score,
            "trust_adjustment": adjustment,
            "combined_score": adjusted_score,
            "full_email_score": adjusted_score,
            "risk_level": level,
            "is_suspicious": (
                adjusted_score >= 40
            ),
            "is_phishing": (
                adjusted_score >= 70
            ),
            "reasons": reasons,
            "domain_trust": trust_result,
        }
    )

    return result

