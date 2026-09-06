from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit


# This is a verified seed registry, not a claim of complete
# worldwide coverage. Unknown domains remain neutral.
VERIFIED_OFFICIAL_DOMAINS: dict[str, str] = {
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "nvidia.com": "NVIDIA",
    "github.com": "GitHub",
    "python.org": "Python Software Foundation",
    "amazon.com": "Amazon",
    "linkedin.com": "LinkedIn",
    "gwu.edu": "The George Washington University",
    "isro.gov.in": "Indian Space Research Organisation",
}


def normalize_hostname(value: str | None) -> str:
    cleaned = str(value or "").strip().lower()

    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        hostname = urlsplit(cleaned).hostname or ""
    except ValueError:
        return ""

    hostname = hostname.strip().lower().rstrip(".")

    if hostname.startswith("*."):
        hostname = hostname[2:]

    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def same_host_or_true_subdomain(
    candidate: str | None,
    official: str | None,
) -> bool:
    candidate_host = normalize_hostname(candidate)
    official_host = normalize_hostname(official)

    if not candidate_host or not official_host:
        return False

    try:
        return (
            ipaddress.ip_address(candidate_host)
            == ipaddress.ip_address(official_host)
        )
    except ValueError:
        pass

    return bool(
        candidate_host == official_host
        or candidate_host.endswith("." + official_host)
    )


def verified_owner(hostname: str | None) -> dict[str, Any] | None:
    normalized = normalize_hostname(hostname)

    if not normalized:
        return None

    for official_domain, organization in VERIFIED_OFFICIAL_DOMAINS.items():
        if same_host_or_true_subdomain(
            normalized,
            official_domain,
        ):
            return {
                "organization": organization,
                "official_domain": official_domain,
                "hostname": normalized,
                "match_type": (
                    "exact"
                    if normalized == official_domain
                    else "true_subdomain"
                ),
                "identity_confidence": 1.0,
            }

    return None


def _collect_candidate_iocs(
    value: Any,
) -> list[str]:
    collected: list[str] = []

    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()

            if isinstance(child, str) and any(
                term in lowered
                for term in (
                    "ioc",
                    "indicator",
                    "hostname",
                    "domain",
                    "url",
                )
            ):
                collected.append(child)

            collected.extend(
                _collect_candidate_iocs(child)
            )

    elif isinstance(value, list):
        for child in value:
            collected.extend(
                _collect_candidate_iocs(child)
            )

    return list(dict.fromkeys(collected))


def relevant_threatfox_iocs(
    payload: dict[str, Any] | None,
    requested_hostname: str,
) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []

    for raw_ioc in _collect_candidate_iocs(payload or {}):
        candidate = normalize_hostname(raw_ioc)

        if same_host_or_true_subdomain(
            candidate,
            requested_hostname,
        ):
            matches.append(
                {
                    "raw_ioc": raw_ioc,
                    "hostname": candidate,
                    "match_type": (
                        "exact"
                        if candidate
                        == normalize_hostname(requested_hostname)
                        else "true_subdomain"
                    ),
                }
            )

    return matches


def sanitize_threatfox(
    payload: dict[str, Any] | None,
    requested_hostname: str,
) -> dict[str, Any]:
    result = dict(payload or {})

    original_match = bool(
        result.get("matched", False)
        or result.get("detected", False)
        or result.get("match", False)
    )

    matches = relevant_threatfox_iocs(
        result,
        requested_hostname,
    )

    relevant_match = bool(
        original_match
        and matches
    )

    result.update(
        {
            "original_match_claimed": original_match,
            "relevance_validated": True,
            "relevant_iocs": matches,
            "matched": relevant_match,
            "false_positive_filtered": bool(
                original_match
                and not relevant_match
            ),
        }
    )

    if original_match and not relevant_match:
        for key in (
            "risk_adjustment",
            "score_adjustment",
            "requested_score_adjustment",
            "applied_score_adjustment",
        ):
            result[key] = 0.0

        result["filter_reason"] = (
            "No returned IOC exactly matched the requested "
            "hostname or one of its true subdomains."
        )

    return result


def apply_domain_trust_guard(
    result: dict[str, Any],
    value: str,
) -> dict[str, Any]:
    guarded = dict(result)

    hostname = normalize_hostname(value)
    owner = verified_owner(hostname)

    original_score = float(
        guarded.get(
            "final_score",
            guarded.get("risk_score", 0.0),
        )
        or 0.0
    )

    hybrid_score = float(
        guarded.get(
            "base_hybrid_score",
            (
                guarded.get(
                    "hybrid_detection",
                    {},
                )
                or {}
            ).get(
                "final_score",
                original_score,
            ),
        )
        or 0.0
    )

    original_threatfox = dict(
        guarded.get(
            "threatfox_intelligence",
            {},
        )
        or {}
    )

    threatfox = sanitize_threatfox(
        original_threatfox,
        hostname,
    )

    guarded["threatfox_intelligence"] = threatfox

    false_positive_filtered = bool(
        threatfox.get(
            "false_positive_filtered",
            False,
        )
    )

    brand = dict(
        guarded.get(
            "global_brand_intelligence",
            {},
        )
        or {}
    )

    if owner:
        brand.update(
            {
                "official_domain_match": True,
                "impersonation_detected": False,
                "matched_brand": owner["organization"],
                "official_domain": owner["official_domain"],
                "official_hostname": owner["hostname"],
                "identity_confidence": 100.0,
                "identity_source": "verified_domain_registry",
            }
        )

    guarded["global_brand_intelligence"] = brand

    total_adjustment = float(
        guarded.get(
            "total_intelligence_adjustment",
            0.0,
        )
        or 0.0
    )

    corrected_score = original_score

    if false_positive_filtered:
        # The trace showed that the erroneous ThreatFox match supplied
        # a +30 adjustment and an 85-point minimum score. Remove that
        # contribution and recompute from the guarded hybrid score.
        corrected_adjustment = max(
            0.0,
            total_adjustment - 30.0,
        )

        corrected_score = (
            hybrid_score
            + corrected_adjustment
        )

    # Verified identity blocks weak isolated reputation evidence from
    # forcing a phishing verdict. Strong exact IOC evidence is retained.
    if (
        owner
        and not threatfox.get("matched", False)
        and corrected_score >= 60
    ):
        vt = dict(
            guarded.get(
                "virustotal_intelligence",
                {},
            )
            or {}
        )

        malicious_count = int(
            vt.get(
                "maximum_malicious",
                0,
            )
            or 0
        )

        impersonation = bool(
            brand.get(
                "impersonation_detected",
                False,
            )
        )

        if (
            malicious_count < 3
            and not impersonation
        ):
            corrected_score = min(
                corrected_score,
                34.0,
            )

    corrected_score = round(
        max(
            0.0,
            min(
                corrected_score,
                100.0,
            ),
        ),
        2,
    )

    if corrected_score >= 80:
        risk_level = "critical"
        classification = "likely_phishing"
    elif corrected_score >= 60:
        risk_level = "high"
        classification = "high_risk"
    elif corrected_score >= 35:
        risk_level = "moderate"
        classification = "needs_review"
    else:
        risk_level = "low"
        classification = "likely_legitimate"

    guarded.update(
        {
            "legacy_score_before_domain_guard": original_score,
            "final_score": corrected_score,
            "risk_score": corrected_score,
            "risk_level": risk_level,
            "classification": classification,
            "is_phishing": corrected_score >= 60,
        }
    )

    reasons = list(
        guarded.get(
            "reasons",
            [],
        )
        or []
    )

    if false_positive_filtered:
        reasons = [
            reason
            for reason in reasons
            if not (
                "threatfox" in str(reason).lower()
                and any(
                    word in str(reason).lower()
                    for word in (
                        "matched",
                        "malicious",
                        "ioc",
                    )
                )
            )
        ]

        reasons.append(
            "ThreatFox Safety Guard: an unrelated IOC was "
            "discarded because its hostname did not match the "
            "requested domain or a true subdomain."
        )

    if owner:
        reasons.append(
            "Identity Evidence: this hostname belongs to the "
            f"verified official domain {owner['official_domain']} "
            f"for {owner['organization']}."
        )

    guarded["reasons"] = list(
        dict.fromkeys(reasons)
    )

    guarded["domain_trust_guard"] = {
        "enabled": True,
        "requested_hostname": hostname,
        "verified_owner": owner,
        "threatfox_relevance_validated": True,
        "threatfox_relevant_match": bool(
            threatfox.get("matched", False)
        ),
        "threatfox_false_positive_filtered": (
            false_positive_filtered
        ),
        "legacy_score": original_score,
        "guarded_score": corrected_score,
    }

    return guarded
