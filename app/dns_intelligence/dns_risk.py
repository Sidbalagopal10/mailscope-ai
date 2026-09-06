from __future__ import annotations

from typing import Any


def dns_risk_evidence(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert DNS observations into bounded evidence.

    Missing email-authentication records are weak signals only.
    Domains that do not send email may legitimately have no MX,
    SPF, or DMARC records.
    """
    if not observation:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "No DNS observation is available."
            ],
        }

    if observation.get(
        "lookup_status"
    ) not in {
        "success",
        "limited",
    }:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                (
                    "DNS data was unavailable. Missing DNS "
                    "data does not independently prove phishing."
                )
            ],
        }

    adjustment = 0.0
    confidence_adjustment = 4.0

    weak_signals = []
    positive_signals = []
    reasons = []

    has_a = bool(
        observation.get(
            "has_a"
        )
    )

    has_aaaa = bool(
        observation.get(
            "has_aaaa"
        )
    )

    has_mx = bool(
        observation.get(
            "has_mx"
        )
    )

    has_spf = bool(
        observation.get(
            "has_spf"
        )
    )

    has_dmarc = bool(
        observation.get(
            "has_dmarc"
        )
    )

    has_caa = bool(
        observation.get(
            "has_caa"
        )
    )

    has_dnssec = bool(
        observation.get(
            "has_dnssec_delegation"
        )
    )

    mx_count = int(
        observation.get(
            "mx_count",
            0,
        )
        or 0
    )

    ns_count = int(
        observation.get(
            "ns_count",
            0,
        )
        or 0
    )

    if not has_a and not has_aaaa:
        weak_signals.append(
            "No directly resolved A or AAAA address"
        )

        reasons.append(
            "The queried domain did not directly resolve to "
            "an IPv4 or IPv6 address."
        )

        adjustment += 2.0

    if not has_mx:
        weak_signals.append(
            "No MX mail-server record"
        )

        reasons.append(
            "No MX record was found. This is only weak "
            "evidence because some domains do not send email."
        )

        adjustment += 1.0

    else:
        positive_signals.append(
            "MX mail infrastructure is configured"
        )

        confidence_adjustment += 1.0

    if has_mx and not has_spf:
        weak_signals.append(
            "Mail-capable domain has no visible SPF record"
        )

        reasons.append(
            "The domain has MX records but no visible SPF "
            "policy at the queried domain."
        )

        adjustment += 1.5

    elif has_spf:
        positive_signals.append(
            "SPF policy is present"
        )

        adjustment -= 0.5

    if has_mx and not has_dmarc:
        weak_signals.append(
            "Mail-capable domain has no visible DMARC record"
        )

        reasons.append(
            "The domain has MX records but no visible DMARC "
            "policy at its organizational domain."
        )

        adjustment += 1.5

    elif has_dmarc:
        positive_signals.append(
            "DMARC policy is present"
        )

        adjustment -= 0.5

    if mx_count >= 2:
        positive_signals.append(
            "Multiple MX servers provide mail redundancy"
        )

        confidence_adjustment += 1.0

    if ns_count >= 2:
        positive_signals.append(
            "Multiple authoritative nameservers are configured"
        )

    elif ns_count == 0:
        weak_signals.append(
            "No authoritative NS records were observed"
        )

        adjustment += 2.0

    if has_caa:
        positive_signals.append(
            "CAA certificate-authority policy is present"
        )

        confidence_adjustment += 1.0

    if has_dnssec:
        positive_signals.append(
            "DNSSEC delegation evidence is present"
        )

        confidence_adjustment += 2.0

    return {
        "available": True,
        "risk_adjustment": round(
            max(
                -3.0,
                min(
                    adjustment,
                    8.0,
                ),
            ),
            2,
        ),
        "confidence_adjustment": round(
            min(
                confidence_adjustment,
                10.0,
            ),
            2,
        ),
        "weak_signals": weak_signals,
        "positive_signals": positive_signals,
        "reasons": reasons,
        "important_limitations": [
            (
                "Missing SPF or DMARC is not proof of phishing."
            ),
            (
                "A domain without MX may simply not send email."
            ),
            (
                "A DS record indicates DNSSEC delegation "
                "evidence; it is not full chain validation."
            ),
            (
                "DKIM cannot be checked without one or more "
                "known selectors."
            ),
        ],
    }
