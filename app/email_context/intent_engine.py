from __future__ import annotations

import re
from typing import Any


URGENCY_PATTERNS = {
    "deadline_language": [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bas soon as possible\b",
        r"\basap\b",
        r"\bby end of day\b",
        r"\beod\b",
        r"\bwithin \d+ (?:minutes?|hours?|days?)\b",
        r"\btoday\b",
        r"\btonight\b",
        r"\blast minute\b",
        r"\btime[- ]sensitive\b",
        r"\baction required\b",
    ],
    "pressure_language": [
        r"\bdo not delay\b",
        r"\bfinal warning\b",
        r"\baccount will be (?:closed|disabled|suspended)\b",
        r"\bfailure to respond\b",
        r"\bavoid (?:termination|suspension|penalty)\b",
    ],
    "secrecy_language": [
        r"\bkeep this confidential\b",
        r"\bdo not tell\b",
        r"\bbetween you and me\b",
        r"\bdo not contact\b",
    ],
}


INTENT_PATTERNS = {
    "academic_deadline": [
        r"\bassignment\b",
        r"\bhomework\b",
        r"\bproject\b",
        r"\bsubmission\b",
        r"\bsubmit\b",
        r"\bdeadline\b",
        r"\bcanvas\b",
        r"\bblackboard\b",
        r"\bgrade(?:s|book)?\b",
        r"\bexam\b",
        r"\bquiz\b",
    ],
    "meeting_request": [
        r"\bmeeting\b",
        r"\bcalendar\b",
        r"\bappointment\b",
        r"\bzoom\b",
        r"\bteams meeting\b",
        r"\bgoogle meet\b",
        r"\bconference call\b",
        r"\breschedule\b",
        r"\bjoin us\b",
    ],
    "work_request": [
        r"\breport\b",
        r"\bpresentation\b",
        r"\bspreadsheet\b",
        r"\bclient\b",
        r"\bdeliverable\b",
        r"\breview this\b",
        r"\bsend me\b",
        r"\bcomplete this\b",
        r"\btask\b",
    ],
    "credential_request": [
        r"\bverify (?:your )?(?:account|identity|password)\b",
        r"\blog[ -]?in\b",
        r"\bsign[ -]?in\b",
        r"\bpassword\b",
        r"\bcredentials?\b",
        r"\bmulti[- ]factor\b",
        r"\bmfa\b",
        r"\bsecurity verification\b",
        r"\bre-authenticate\b",
    ],
    "financial_request": [
        r"\bwire transfer\b",
        r"\bbank transfer\b",
        r"\bpayment\b",
        r"\bpayroll\b",
        r"\bdirect deposit\b",
        r"\baccount number\b",
        r"\brouting number\b",
        r"\bbitcoin\b",
        r"\bcrypto(?:currency)?\b",
        r"\bwallet\b",
    ],
    "gift_card_request": [
        r"\bgift cards?\b",
        r"\bitunes cards?\b",
        r"\bgoogle play cards?\b",
        r"\bsteam cards?\b",
        r"\bscratch off the code\b",
        r"\bsend (?:me )?(?:the )?codes?\b",
    ],
    "invoice_request": [
        r"\binvoice\b",
        r"\bpurchase order\b",
        r"\bpo number\b",
        r"\boverdue balance\b",
        r"\bamount due\b",
        r"\bremittance\b",
    ],
    "document_share": [
        r"\bshared (?:a )?(?:document|file|folder)\b",
        r"\bview (?:the )?(?:document|file)\b",
        r"\bdownload (?:the )?(?:document|file)\b",
        r"\bgoogle drive\b",
        r"\bone ?drive\b",
        r"\bsharepoint\b",
        r"\bdropbox\b",
    ],
    "account_security_notice": [
        r"\bsuspicious activity\b",
        r"\bunusual sign[- ]in\b",
        r"\baccount locked\b",
        r"\baccount suspended\b",
        r"\bsecurity alert\b",
        r"\bunauthorized access\b",
    ],
    "informational": [
        r"\bannouncement\b",
        r"\bnewsletter\b",
        r"\breminder\b",
        r"\bfor your information\b",
        r"\bfyi\b",
        r"\bupdate\b",
    ],
}


HIGH_RISK_INTENTS = {
    "credential_request",
    "financial_request",
    "gift_card_request",
    "account_security_notice",
}


NORMAL_URGENCY_INTENTS = {
    "academic_deadline",
    "meeting_request",
    "work_request",
}


def normalize_text(
    value: str | None,
) -> str:
    return re.sub(
        r"\s+",
        " ",
        str(
            value or ""
        ).strip().lower(),
    )


def find_matches(
    text: str,
    patterns: list[str],
) -> list[str]:
    matches: list[str] = []

    for pattern in patterns:
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            matches.append(
                pattern
            )

    return matches


def analyze_urgency(
    subject: str | None,
    body: str | None,
) -> dict[str, Any]:
    text = normalize_text(
        f"{subject or ''} {body or ''}"
    )

    categories: dict[
        str,
        list[str],
    ] = {}

    for category, patterns in URGENCY_PATTERNS.items():
        found = find_matches(
            text,
            patterns,
        )

        if found:
            categories[
                category
            ] = found

    pressure_present = bool(
        categories.get(
            "pressure_language"
        )
    )

    secrecy_present = bool(
        categories.get(
            "secrecy_language"
        )
    )

    deadline_present = bool(
        categories.get(
            "deadline_language"
        )
    )

    score = 0

    if deadline_present:
        score += 25

    if pressure_present:
        score += 40

    if secrecy_present:
        score += 45

    score = min(
        score,
        100,
    )

    if score >= 70:
        level = "high"

    elif score >= 25:
        level = "moderate"

    else:
        level = "none"

    return {
        "detected": bool(
            categories
        ),
        "level": level,
        "score": score,
        "deadline_language": (
            deadline_present
        ),
        "pressure_language": (
            pressure_present
        ),
        "secrecy_language": (
            secrecy_present
        ),
        "matched_categories": (
            categories
        ),
    }


def analyze_intent(
    subject: str | None,
    body: str | None,
) -> dict[str, Any]:
    text = normalize_text(
        f"{subject or ''} {body or ''}"
    )

    findings: list[
        dict[str, Any]
    ] = []

    for intent, patterns in INTENT_PATTERNS.items():
        matches = find_matches(
            text,
            patterns,
        )

        if not matches:
            continue

        findings.append(
            {
                "intent": intent,
                "match_count": len(
                    matches
                ),
                "matched_patterns": (
                    matches
                ),
                "inherent_risk": (
                    "high"
                    if intent
                    in HIGH_RISK_INTENTS
                    else "low"
                    if intent
                    in NORMAL_URGENCY_INTENTS
                    or intent
                    == "informational"
                    else "moderate"
                ),
            }
        )

    findings.sort(
        key=lambda item: (
            item["match_count"],
            1
            if item["intent"]
            in HIGH_RISK_INTENTS
            else 0,
        ),
        reverse=True,
    )

    primary_intent = (
        findings[0][
            "intent"
        ]
        if findings
        else "unknown"
    )

    high_risk_intents = [
        item["intent"]
        for item in findings
        if item["intent"]
        in HIGH_RISK_INTENTS
    ]

    normal_urgency_intents = [
        item["intent"]
        for item in findings
        if item["intent"]
        in NORMAL_URGENCY_INTENTS
    ]

    return {
        "primary_intent": (
            primary_intent
        ),
        "all_intents": [
            item["intent"]
            for item in findings
        ],
        "findings": findings,
        "high_risk_intents": (
            high_risk_intents
        ),
        "normal_urgency_intents": (
            normal_urgency_intents
        ),
    }


def analyze_message_context(
    *,
    subject: str | None,
    body: str | None,
) -> dict[str, Any]:
    urgency = analyze_urgency(
        subject,
        body,
    )

    intent = analyze_intent(
        subject,
        body,
    )

    urgency_consistent_with_intent = bool(
        urgency["detected"]
        and intent[
            "normal_urgency_intents"
        ]
        and not urgency[
            "pressure_language"
        ]
        and not urgency[
            "secrecy_language"
        ]
    )

    urgency_combined_with_high_risk_intent = bool(
        urgency["detected"]
        and intent[
            "high_risk_intents"
        ]
    )

    return {
        "urgency": urgency,
        "intent": intent,
        "urgency_consistent_with_intent": (
            urgency_consistent_with_intent
        ),
        "urgency_combined_with_high_risk_intent": (
            urgency_combined_with_high_risk_intent
        ),
    }

# BEGIN EXTENDED BEC AND FINANCIAL PATTERNS
#
# These patterns cover business-email-compromise wording that may
# avoid the exact phrase "gift card", including prepaid cards,
# photographs of redemption codes, account-change requests, and
# sensitive bank-detail collection.
#
# They extend the existing intent dictionaries without changing
# the original patterns or thresholds.

INTENT_PATTERNS.setdefault(
    "gift_card_request",
    [],
).extend(
    [
        r"\bprepaid cards?\b",
        r"\bstore cards?\b",
        r"\bvouchers?\b",
        r"\brecharge cards?\b",
        r"\bpurchase (?:some |several |\d+ )?(?:prepaid |store )?cards?\b",
        r"\bbuy (?:some |several |\d+ )?(?:prepaid |store )?cards?\b",
        r"\bphotographs? of (?:the )?(?:cards?|codes?)\b",
        r"\bphotos? of (?:the )?(?:cards?|codes?)\b",
        r"\bpictures? of (?:the )?(?:cards?|codes?)\b",
        r"\bsend (?:me )?(?:photos?|photographs?|pictures?)\b",
        r"\bredemption codes?\b",
        r"\bactivation codes?\b",
        r"\bcard numbers? and pins?\b",
        r"\bscratch (?:off|the back)\b",
    ]
)

INTENT_PATTERNS.setdefault(
    "financial_request",
    [],
).extend(
    [
        r"\bbank details?\b",
        r"\bbanking details?\b",
        r"\bpayment details?\b",
        r"\bbeneficiary details?\b",
        r"\bnew bank account\b",
        r"\bchange(?:d)? (?:the )?(?:bank|payment|beneficiary) account\b",
        r"\bupdate (?:the |your )?(?:bank|payment|payroll) details?\b",
        r"\bconfirm (?:the |your )?(?:bank|payment|account) details?\b",
        r"\bsend (?:the )?(?:wire|payment|funds?)\b",
        r"\btransfer (?:the )?(?:money|funds?|payment)\b",
        r"\bmake (?:an? )?(?:urgent )?payment\b",
        r"\bsettle (?:the )?(?:invoice|balance|payment)\b",
        r"\brefund\b",
        r"\bsalary payment\b",
        r"\bdelayed salary\b",
    ]
)

INTENT_PATTERNS.setdefault(
    "credential_request",
    [],
).extend(
    [
        r"\bconfirm (?:your )?(?:login|credentials?|password)\b",
        r"\bprovide (?:your )?(?:login|credentials?|password)\b",
        r"\benter (?:your )?(?:login|credentials?|password)\b",
        r"\bvalidate (?:your )?(?:account|identity|credentials?)\b",
        r"\bunlock (?:your )?account\b",
        r"\brestore (?:your )?account access\b",
        r"\baccess expires?\b",
        r"\bprotected document\b",
    ]
)

URGENCY_PATTERNS.setdefault(
    "secrecy_language",
    [],
).extend(
    [
        r"\bdo not call\b",
        r"\bdon't call\b",
        r"\bdo not phone\b",
        r"\bdon't phone\b",
        r"\bdo not verify\b",
        r"\bdon't verify\b",
        r"\bno need to call\b",
        r"\bhandle this discreetly\b",
        r"\bkeep this between us\b",
    ]
)

URGENCY_PATTERNS.setdefault(
    "pressure_language",
    [],
).extend(
    [
        r"\bneed this handled now\b",
        r"\bhandle this now\b",
        r"\bcomplete it now\b",
        r"\bmust be done today\b",
        r"\bwithout delay\b",
        r"\baccess expires? in\b",
        r"\bpayment will be delayed\b",
        r"\bsalary will be delayed\b",
    ]
)

# END EXTENDED BEC AND FINANCIAL PATTERNS

