from __future__ import annotations

from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from app.trust.domain_store import (
    find_matching_domain,
)


def extract_sender_domain(
    sender: str,
) -> str:
    address = parseaddr(
        str(sender or "")
    )[1].lower()

    if "@" not in address:
        return ""

    return address.rsplit(
        "@",
        1,
    )[1]


def extract_url_hostnames(
    analysis: dict[str, Any],
) -> list[str]:
    hostnames = []

    for result in analysis.get(
        "url_results",
        [],
    ):
        url = str(
            result.get(
                "url",
                "",
            )
        ).strip()

        hostname = (
            urlparse(
                url
            ).hostname
            or ""
        ).lower()

        if hostname:
            hostnames.append(
                hostname
            )

    return sorted(
        set(
            hostnames
        )
    )


def evaluate_domain_trust(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    sender_domain = extract_sender_domain(
        analysis.get(
            "sender",
            "",
        )
    )

    sender_record = find_matching_domain(
        sender_domain
    )

    url_hostnames = extract_url_hostnames(
        analysis
    )

    url_records = []

    for hostname in url_hostnames:
        record = find_matching_domain(
            hostname
        )

        if record:
            url_records.append(
                {
                    "hostname": hostname,
                    **record,
                }
            )

    header_analysis = analysis.get(
        "header_analysis",
        {},
    )

    authentication_passed = all(
        str(
            header_analysis.get(
                key,
                "none",
            )
        ).lower()
        == "pass"
        for key in (
            "spf",
            "dkim",
            "dmarc",
        )
    )

    sender_alignment_ok = not bool(
        header_analysis.get(
            "reply_to_mismatch",
            False,
        )
        or header_analysis.get(
            "return_path_mismatch",
            False,
        )
    )

    brand_impersonation = any(
        bool(
            result.get(
                "brand_intelligence",
                {},
            ).get(
                "impersonation_detected",
                False,
            )
        )
        for result in analysis.get(
            "url_results",
            [],
        )
    )

    suspicious_external_form = any(
        bool(
            result.get(
                "deep_inspection",
                {},
            ).get(
                "external_password_form_count",
                0,
            )
        )
        for result in analysis.get(
            "url_results",
            [],
        )
    )

    sender_status = (
        sender_record.get(
            "status"
        )
        if sender_record
        else "UNKNOWN"
    )

    blocked_url_domains = [
        record
        for record in url_records
        if record.get(
            "status"
        )
        == "BLOCKED"
    ]

    trusted_url_domains = [
        record
        for record in url_records
        if record.get(
            "status"
        )
        == "TRUSTED"
    ]

    safe_trust_conditions = all(
        [
            sender_status == "TRUSTED",
            authentication_passed,
            sender_alignment_ok,
            not brand_impersonation,
            not suspicious_external_form,
            not blocked_url_domains,
        ]
    )

    adjustment = 0.0
    reasons = []

    if sender_status == "BLOCKED":
        adjustment += 35

        reasons.append(
            "The sender domain is explicitly blocked."
        )

    if blocked_url_domains:
        adjustment += 40

        reasons.append(
            "At least one URL domain is explicitly blocked."
        )

    if safe_trust_conditions:
        adjustment -= 18

        reasons.append(
            "The sender is trusted and SPF, DKIM, and DMARC "
            "passed with no major alignment or impersonation issues."
        )

        if trusted_url_domains:
            adjustment -= 7

            reasons.append(
                "One or more destination domains are also trusted."
            )

    elif sender_status == "TRUSTED":
        reasons.append(
            "The sender is listed as trusted, but trust reduction "
            "was not applied because authentication, alignment, or "
            "other security checks did not fully pass."
        )

    adjustment = max(
        min(
            adjustment,
            50,
        ),
        -25,
    )

    return {
        "sender_domain": sender_domain,
        "sender_record": sender_record,
        "sender_status": sender_status,
        "authentication_passed": (
            authentication_passed
        ),
        "sender_alignment_ok": (
            sender_alignment_ok
        ),
        "brand_impersonation_detected": (
            brand_impersonation
        ),
        "trusted_url_domains": (
            trusted_url_domains
        ),
        "blocked_url_domains": (
            blocked_url_domains
        ),
        "score_adjustment": round(
            adjustment,
            2,
        ),
        "reasons": reasons,
        "safe_trust_conditions_met": (
            safe_trust_conditions
        ),
    }
