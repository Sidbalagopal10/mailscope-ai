from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any


AUTH_RISK = {
    "pass": 0,
    "neutral": 8,
    "none": 10,
    "temperror": 12,
    "softfail": 18,
    "permerror": 20,
    "fail": 30,
}


def get_header(
    headers: list[dict[str, Any]],
    name: str,
) -> str:
    for header in headers:
        if str(header.get("name", "")).lower() == name.lower():
            return str(header.get("value", ""))

    return ""


def extract_address(value: str) -> str:
    return parseaddr(value)[1].strip().lower()


def extract_domain(value: str) -> str:
    address = extract_address(value)

    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[1]


def extract_auth_result(
    authentication_results: str,
    mechanism: str,
) -> str:
    match = re.search(
        rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z]+)",
        authentication_results,
        flags=re.IGNORECASE,
    )

    if not match:
        return "none"

    result = match.group(1).lower()

    return result if result in AUTH_RISK else "none"


def determine_risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    if score >= 20:
        return "GUARDED"

    return "LOW"


def analyze_email_headers(
    headers: list[dict[str, Any]],
) -> dict[str, Any]:
    from_value = get_header(headers, "From")
    reply_to_value = get_header(headers, "Reply-To")
    return_path_value = get_header(headers, "Return-Path")
    authentication_results = get_header(
        headers,
        "Authentication-Results",
    )
    received_spf = get_header(headers, "Received-SPF")
    message_id = get_header(headers, "Message-ID")

    from_address = extract_address(from_value)
    reply_to_address = extract_address(reply_to_value)
    return_path_address = extract_address(return_path_value)

    from_domain = extract_domain(from_value)
    reply_to_domain = extract_domain(reply_to_value)
    return_path_domain = extract_domain(return_path_value)

    spf = extract_auth_result(authentication_results, "spf")
    dkim = extract_auth_result(authentication_results, "dkim")
    dmarc = extract_auth_result(authentication_results, "dmarc")

    if spf == "none" and received_spf:
        possible_spf = received_spf.split(" ", 1)[0].strip().lower()

        if possible_spf in AUTH_RISK:
            spf = possible_spf

    score = 0.0
    reasons: list[str] = []
    indicators: list[dict[str, Any]] = []

    for mechanism, result in {
        "SPF": spf,
        "DKIM": dkim,
        "DMARC": dmarc,
    }.items():
        contribution = AUTH_RISK[result]
        score += contribution

        if result != "pass":
            explanation = (
                f"{mechanism} authentication resulted in {result}."
            )

            reasons.append(explanation)

            indicators.append(
                {
                    "category": mechanism.lower(),
                    "result": result,
                    "score": contribution,
                    "explanation": explanation,
                }
            )

    reply_to_mismatch = bool(
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    )

    if reply_to_mismatch:
        score += 18
        explanation = (
            "The Reply-To domain differs from the visible From domain."
        )
        reasons.append(explanation)
        indicators.append(
            {
                "category": "reply_to_mismatch",
                "result": "mismatch",
                "score": 18,
                "explanation": explanation,
            }
        )

    return_path_mismatch = bool(
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    )

    if return_path_mismatch:
        score += 10
        explanation = (
            "The Return-Path domain differs from the visible From domain."
        )
        reasons.append(explanation)
        indicators.append(
            {
                "category": "return_path_mismatch",
                "result": "mismatch",
                "score": 10,
                "explanation": explanation,
            }
        )

    if not message_id.strip():
        score += 5
        explanation = "The message does not contain a Message-ID header."
        reasons.append(explanation)
        indicators.append(
            {
                "category": "missing_message_id",
                "result": "missing",
                "score": 5,
                "explanation": explanation,
            }
        )

    final_score = round(min(score, 100), 2)
    risk_level = determine_risk_level(final_score)

    if not reasons:
        reasons.append(
            "SPF, DKIM, and DMARC passed, with no major "
            "sender-domain mismatches detected."
        )

    if final_score >= 60:
        recommendation = (
            "Treat the sender as untrusted and verify the message "
            "through an independent communication channel."
        )
    elif final_score >= 40:
        recommendation = (
            "Review the sender carefully before clicking links or replying."
        )
    elif final_score >= 20:
        recommendation = (
            "Some header anomalies were detected. Verify the sender."
        )
    else:
        recommendation = (
            "No strong email-authentication problems were detected."
        )

    return {
        "from": from_value,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to": reply_to_value,
        "reply_to_address": reply_to_address,
        "reply_to_domain": reply_to_domain,
        "return_path": return_path_value,
        "return_path_address": return_path_address,
        "return_path_domain": return_path_domain,
        "message_id": message_id,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "all_authentication_passed": all(
            result == "pass"
            for result in (spf, dkim, dmarc)
        ),
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "header_score": final_score,
        "risk_level": risk_level,
        "is_suspicious": final_score >= 40,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "reasons": reasons,
        "recommendation": recommendation,
    }
