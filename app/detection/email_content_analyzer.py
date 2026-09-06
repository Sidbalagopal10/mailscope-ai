from __future__ import annotations

import re
from typing import Any


URGENCY_PATTERNS = (
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact now\b",
    r"\bwithin 24 hours\b",
    r"\bfinal warning\b",
    r"\bwithout delay\b",
)


CREDENTIAL_PATTERNS = (
    r"\bverify (your )?(account|identity|password)\b",
    r"\bconfirm (your )?(identity|password)\b",
    r"\benter (your )?(password|credentials|login)\b",
    r"\bprovide (your )?(password|credentials|login)\b",
    r"\bone[- ]time password\b",
    r"\botp\b",
)


HIGH_RISK_FINANCIAL_PATTERNS = (
    r"\bwire transfer\b",
    r"\bgift cards?\b",
    r"\bbitcoin\b",
    r"\bcrypto(currency)?\b",
    r"\bbank details?\b",
    r"\brouting number\b",
    r"\bpay immediately\b",
    r"\bpurchase equipment\b",
    r"\bmobile deposit\b",
    r"\bdeposit (the|this) check\b",
)


NORMAL_FINANCIAL_TERMS = (
    r"\binvoice\b",
    r"\bpayment\b",
    r"\bbilling\b",
    r"\bbank\b",
    r"\baccount\b",
    r"\bstatement\b",
    r"\btransaction\b",
    r"\brefund\b",
    r"\bpayroll\b",
)


JOB_SCAM_PATTERNS = (
    r"\btelegram interview\b",
    r"\bwhatsapp interview\b",
    r"\btext interview\b",
    r"\bno interview required\b",
    r"\bbuy (your own )?equipment\b",
    r"\bequipment reimbursement\b",
    r"\bwe will send (you )?a check\b",
    r"\bdeposit (the|this) check\b",
    r"\bgift card\b",
    r"\bcrypto payment\b",
)


NORMAL_JOB_PATTERNS = (
    r"\bjob application\b",
    r"\bapplication received\b",
    r"\bapplication status\b",
    r"\binterview schedule\b",
    r"\brecruiter\b",
    r"\bposition\b",
    r"\bcandidate\b",
    r"\bjob alert\b",
)


THREAT_PATTERNS = (
    r"\baccount (will be|has been) "
    r"(closed|suspended|locked)\b",
    r"\baccess (will be|has been) "
    r"(disabled|revoked)\b",
    r"\blegal action\b",
    r"\blocked out\b",
)


SECRECY_PATTERNS = (
    r"\bkeep this confidential\b",
    r"\bdo not tell\b",
    r"\bdo not contact\b",
    r"\bdo not discuss\b",
)


CALL_TO_ACTION_PATTERNS = (
    r"\bclick (here|below|the link)\b",
    r"\bfollow the link\b",
    r"\bopen the attachment\b",
    r"\bscan the qr code\b",
    r"\bcomplete the form\b",
)


def matches(
    text: str,
    patterns: tuple[str, ...],
) -> list[str]:
    return [
        pattern
        for pattern in patterns
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        )
    ]


def risk_level(
    score: float,
) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    if score >= 20:
        return "GUARDED"

    return "LOW"


def analyze_email_content(
    subject: str,
    body: str,
    sender: str | None = None,
) -> dict[str, Any]:
    subject = str(
        subject or ""
    ).strip()

    body = str(
        body or ""
    ).strip()

    sender = str(
        sender or ""
    ).strip()

    text = (
        f"{subject}\n{body}"
    )

    groups = {
        "urgency": matches(
            text,
            URGENCY_PATTERNS,
        ),
        "credential_request": matches(
            text,
            CREDENTIAL_PATTERNS,
        ),
        "high_risk_financial": matches(
            text,
            HIGH_RISK_FINANCIAL_PATTERNS,
        ),
        "normal_financial": matches(
            text,
            NORMAL_FINANCIAL_TERMS,
        ),
        "job_scam": matches(
            text,
            JOB_SCAM_PATTERNS,
        ),
        "normal_job": matches(
            text,
            NORMAL_JOB_PATTERNS,
        ),
        "threat": matches(
            text,
            THREAT_PATTERNS,
        ),
        "secrecy": matches(
            text,
            SECRECY_PATTERNS,
        ),
        "call_to_action": matches(
            text,
            CALL_TO_ACTION_PATTERNS,
        ),
    }

    score = 0.0
    indicators = []
    reasons = []

    def add(
        category: str,
        contribution: float,
        explanation: str,
    ) -> None:
        nonlocal score

        score += contribution

        indicators.append(
            {
                "category": category,
                "score": contribution,
                "match_count": len(
                    groups.get(
                        category,
                        [],
                    )
                ),
                "explanation": explanation,
            }
        )

        reasons.append(
            explanation
        )

    if groups["urgency"]:
        add(
            "urgency",
            10,
            "The message applies urgency "
            "or time pressure.",
        )

    if groups[
        "credential_request"
    ]:
        add(
            "credential_request",
            24,
            "The message requests credentials "
            "or identity verification.",
        )

    if groups[
        "high_risk_financial"
    ]:
        add(
            "high_risk_financial",
            22,
            "The message contains an unusual "
            "or high-risk financial request.",
        )

    if groups["job_scam"]:
        add(
            "job_scam",
            25,
            "The message contains patterns "
            "commonly associated with job scams.",
        )

    if groups["threat"]:
        add(
            "threat",
            15,
            "The message uses threats or "
            "account-access penalties.",
        )

    if groups["secrecy"]:
        add(
            "secrecy",
            13,
            "The message discourages "
            "independent verification.",
        )

    if groups[
        "call_to_action"
    ]:
        add(
            "call_to_action",
            6,
            "The message asks the recipient "
            "to click, open, or submit something.",
        )

    # Ordinary financial and employment language
    # is contextual information, not independent
    # phishing evidence.
    if groups[
        "normal_financial"
    ]:
        indicators.append(
            {
                "category": (
                    "normal_financial_context"
                ),
                "score": 0,
                "match_count": len(
                    groups[
                        "normal_financial"
                    ]
                ),
                "explanation": (
                    "Routine financial terminology "
                    "was detected but was not treated "
                    "as phishing by itself."
                ),
            }
        )

    if groups["normal_job"]:
        indicators.append(
            {
                "category": (
                    "normal_job_context"
                ),
                "score": 0,
                "match_count": len(
                    groups[
                        "normal_job"
                    ]
                ),
                "explanation": (
                    "Routine recruiting or job-"
                    "application terminology was "
                    "detected but was not treated "
                    "as phishing by itself."
                ),
            }
        )

    # Combination-based escalation.
    if (
        groups["urgency"]
        and groups[
            "credential_request"
        ]
    ):
        score += 12
        reasons.append(
            "Urgency appears together with "
            "a credential request."
        )

    if (
        groups[
            "normal_financial"
        ]
        and groups[
            "credential_request"
        ]
    ):
        score += 8
        reasons.append(
            "Financial context appears together "
            "with a credential request."
        )

    if (
        groups[
            "high_risk_financial"
        ]
        and groups["urgency"]
    ):
        score += 10
        reasons.append(
            "An unusual financial request is "
            "combined with urgency."
        )

    if (
        groups["job_scam"]
        and groups[
            "high_risk_financial"
        ]
    ):
        score += 12
        reasons.append(
            "Job-scam indicators appear together "
            "with a financial request."
        )

    if (
        groups["normal_job"]
        and not groups["job_scam"]
        and not groups[
            "credential_request"
        ]
        and not groups[
            "high_risk_financial"
        ]
    ):
        score = max(
            score - 5,
            0,
        )

    if (
        groups[
            "normal_financial"
        ]
        and not groups[
            "credential_request"
        ]
        and not groups[
            "high_risk_financial"
        ]
        and not groups["urgency"]
    ):
        score = max(
            score - 5,
            0,
        )

    final_score = round(
        min(
            max(
                score,
                0,
            ),
            100,
        ),
        2,
    )

    if not reasons:
        reasons.append(
            "No strong social-engineering "
            "combinations were detected."
        )

    return {
        "subject": subject,
        "sender": sender,
        "content_score": final_score,
        "risk_level": (
            risk_level(
                final_score
            )
        ),
        "is_suspicious": (
            final_score >= 40
        ),
        "indicator_count": len(
            indicators
        ),
        "indicators": indicators,
        "reasons": reasons,
        "recommendation": (
            "Do not provide credentials or "
            "send money; verify the request "
            "independently."
            if final_score >= 60
            else (
                "Verify the sender before "
                "taking action."
                if final_score >= 40
                else (
                    "No strong content-based "
                    "phishing evidence was found."
                )
            )
        ),
        "analysis_type": (
            "context-aware-email-content-v2"
        ),
    }
