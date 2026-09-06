from __future__ import annotations

from typing import Any


MAJOR_SHARED_INFRASTRUCTURE_TERMS = {
    "akamai",
    "amazon",
    "aws",
    "cloudflare",
    "fastly",
    "google",
    "microsoft",
    "oracle",
}


def ip_asn_risk_evidence(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert IP and ASN facts into bounded evidence.

    Hosting provider identity never proves that a tenant domain
    is legitimate or malicious.
    """
    if not observation:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "No IP or ASN observation is available."
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
                    "IP and ASN evidence was unavailable. "
                    "This does not add risk."
                )
            ],
        }

    adjustment = 0.0
    confidence_adjustment = 3.0

    weak_signals = []
    positive_signals = []
    reasons = []

    public_addresses = observation.get(
        "public_addresses",
        [],
    )

    unique_asns = observation.get(
        "unique_asns",
        [],
    )

    network_names = [
        str(
            value
        ).lower()
        for value in observation.get(
            "unique_network_names",
            [],
        )
    ]

    reverse_names = [
        name
        for item in observation.get(
            "reverse_dns",
            [],
        )
        for name in item.get(
            "names",
            [],
        )
    ]

    if not public_addresses:
        weak_signals.append(
            "No public destination IP address was resolved"
        )

        adjustment += 2.0

        reasons.append(
            "The hostname did not resolve to a public address."
        )

    if public_addresses:
        positive_signals.append(
            "At least one public destination address resolved"
        )

    if len(
        public_addresses
    ) >= 2:
        positive_signals.append(
            "Multiple destination addresses were observed"
        )

        confidence_adjustment += 1.0

    if not unique_asns and public_addresses:
        weak_signals.append(
            "ASN ownership could not be identified"
        )

        adjustment += 1.0

    elif unique_asns:
        positive_signals.append(
            "Origin ASN ownership was identified"
        )

        confidence_adjustment += 2.0

    if reverse_names:
        positive_signals.append(
            "Reverse-DNS names were observed"
        )

    uses_major_shared_infrastructure = any(
        term in network_name
        for network_name in network_names
        for term in MAJOR_SHARED_INFRASTRUCTURE_TERMS
    )

    if uses_major_shared_infrastructure:
        reasons.append(
            "The domain appears to use major shared or cloud "
            "infrastructure. This is neutral because legitimate "
            "and malicious tenants can use the same provider."
        )

    return {
        "available": True,
        "risk_adjustment": round(
            max(
                -1.0,
                min(
                    adjustment,
                    4.0,
                ),
            ),
            2,
        ),
        "confidence_adjustment": round(
            min(
                confidence_adjustment,
                8.0,
            ),
            2,
        ),
        "weak_signals": weak_signals,
        "positive_signals": positive_signals,
        "reasons": reasons,
        "uses_major_shared_infrastructure": (
            uses_major_shared_infrastructure
        ),
        "important_limitations": [
            (
                "ASN ownership identifies network infrastructure, "
                "not necessarily the organization operating the domain."
            ),
            (
                "Cloud and CDN providers host both legitimate and "
                "malicious customers."
            ),
            (
                "Reverse DNS can be missing or controlled by the "
                "network provider."
            ),
            (
                "IP reputation is not included yet."
            ),
        ],
    }
