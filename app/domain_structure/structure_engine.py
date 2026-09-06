from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.benchmarking.structural_features import (
    extract_structural_features,
)


@dataclass
class StructuralFinding:
    name: str
    points: float
    severity: str
    reason: str


def analyze_structure(
    value: str,
) -> dict[str, Any]:
    features = extract_structural_features(
        value
    )

    if not features:
        return {
            "score": 0.0,
            "confidence": 0.0,
            "findings": [],
            "features": {},
        }

    findings: list[StructuralFinding] = []

    def add(
        name: str,
        points: float,
        severity: str,
        reason: str,
    ) -> None:
        findings.append(
            StructuralFinding(
                name=name,
                points=points,
                severity=severity,
                reason=reason,
            )
        )

    # ------------------------------------------------
    # URL / HOSTNAME SIZE
    #
    # Phishing mean:
    # URL      ~47
    # hostname ~26
    #
    # Benign mean:
    # URL      ~20
    # hostname ~11
    #
    # Still treated as weak evidence individually.
    # ------------------------------------------------

    url_length = int(
        features.get(
            "url_length",
            0,
        )
    )

    hostname_length = int(
        features.get(
            "hostname_length",
            0,
        )
    )

    if url_length >= 80:
        add(
            "very_long_url",
            8.0,
            "moderate",
            f"URL length is {url_length}.",
        )

    elif url_length >= 45:
        add(
            "long_url",
            4.0,
            "weak",
            f"URL length is {url_length}.",
        )

    if hostname_length >= 40:
        add(
            "very_long_hostname",
            8.0,
            "moderate",
            (
                f"Hostname length is "
                f"{hostname_length}."
            ),
        )

    elif hostname_length >= 24:
        add(
            "long_hostname",
            4.0,
            "weak",
            (
                f"Hostname length is "
                f"{hostname_length}."
            ),
        )

    # ------------------------------------------------
    # SUBDOMAIN COMPLEXITY
    # ------------------------------------------------

    depth = int(
        features.get(
            "subdomain_depth",
            0,
        )
    )

    if depth >= 4:
        add(
            "deep_subdomain_chain",
            10.0,
            "moderate",
            (
                f"Hostname contains approximately "
                f"{depth} subdomain levels."
            ),
        )

    elif depth >= 2:
        add(
            "multiple_subdomains",
            5.0,
            "weak",
            (
                f"Hostname contains approximately "
                f"{depth} subdomain levels."
            ),
        )

    longest_label = int(
        features.get(
            "longest_label_length",
            0,
        )
    )

    if longest_label >= 30:
        add(
            "very_long_domain_label",
            8.0,
            "moderate",
            (
                "A hostname label is unusually long "
                f"({longest_label} characters)."
            ),
        )

    elif longest_label >= 16:
        add(
            "long_domain_label",
            4.0,
            "weak",
            (
                "A hostname label is relatively long "
                f"({longest_label} characters)."
            ),
        )

    # ------------------------------------------------
    # ENTROPY / RANDOMNESS
    # ------------------------------------------------

    hostname_entropy = float(
        features.get(
            "hostname_entropy",
            0.0,
        )
    )

    if hostname_entropy >= 4.2:
        add(
            "very_high_hostname_entropy",
            10.0,
            "moderate",
            (
                "Hostname character distribution appears "
                "highly irregular."
            ),
        )

    elif hostname_entropy >= 3.75:
        add(
            "high_hostname_entropy",
            5.0,
            "weak",
            (
                "Hostname has elevated character entropy."
            ),
        )

    # ------------------------------------------------
    # DIGITS / HYPHENS
    # ------------------------------------------------

    digit_ratio = float(
        features.get(
            "digit_ratio",
            0.0,
        )
    )

    digit_count = int(
        features.get(
            "digit_count",
            0,
        )
    )

    if digit_ratio >= 0.20:
        add(
            "high_digit_ratio",
            8.0,
            "moderate",
            (
                "Hostname contains an unusually high "
                "proportion of digits."
            ),
        )

    elif digit_count >= 3:
        add(
            "multiple_digits",
            4.0,
            "weak",
            (
                f"Hostname contains {digit_count} digits."
            ),
        )

    hyphen_count = int(
        features.get(
            "hyphen_count",
            0,
        )
    )

    if hyphen_count >= 3:
        add(
            "many_hyphens",
            8.0,
            "moderate",
            (
                f"Hostname contains "
                f"{hyphen_count} hyphens."
            ),
        )

    elif hyphen_count >= 1:
        add(
            "hostname_hyphen",
            2.0,
            "weak",
            "Hostname contains a hyphen.",
        )

    # ------------------------------------------------
    # HIGH-SIGNAL STRUCTURAL FEATURES
    # ------------------------------------------------

    if features.get(
        "contains_punycode"
    ):
        add(
            "punycode_hostname",
            14.0,
            "strong",
            (
                "Hostname uses IDN/Punycode encoding. "
                "This requires additional impersonation checks."
            ),
        )

    if features.get(
        "hostname_is_ip"
    ):
        add(
            "raw_ip_hostname",
            16.0,
            "strong",
            (
                "The URL uses an IP address instead "
                "of a registered hostname."
            ),
        )

    if features.get(
        "contains_at_symbol"
    ):
        add(
            "at_symbol_obfuscation",
            16.0,
            "strong",
            (
                "The URL contains an @ symbol that can "
                "obscure the effective destination."
            ),
        )

    if features.get(
        "repeated_separator"
    ):
        add(
            "repeated_separator",
            6.0,
            "moderate",
            (
                "URL contains unusual repeated separators."
            ),
        )

    if features.get(
        "non_standard_port"
    ):
        add(
            "non_standard_port",
            6.0,
            "moderate",
            (
                "URL uses a non-standard network port."
            ),
        )

    # ------------------------------------------------
    # CREDENTIAL / SECURITY LANGUAGE
    # ------------------------------------------------

    sensitive_count = int(
        features.get(
            "sensitive_term_count",
            0,
        )
    )

    sensitive_terms = features.get(
        "sensitive_terms",
        [],
    )

    if sensitive_count >= 3:
        add(
            "multiple_sensitive_terms",
            12.0,
            "strong",
            (
                "URL contains multiple credential/security "
                "terms: "
                + ", ".join(
                    sensitive_terms[:5]
                )
            ),
        )

    elif sensitive_count >= 1:
        add(
            "sensitive_term",
            6.0,
            "moderate",
            (
                "URL contains a credential/security term: "
                + ", ".join(
                    sensitive_terms[:3]
                )
            ),
        )

    # ------------------------------------------------
    # BRAND TOKENS
    #
    # Brand presence alone is NOT enough.
    # It becomes useful when identity is unknown.
    # ------------------------------------------------

    brand_count = int(
        features.get(
            "brand_token_count",
            0,
        )
    )

    brand_tokens = features.get(
        "brand_tokens",
        [],
    )

    if brand_count >= 2:
        add(
            "multiple_brand_tokens",
            8.0,
            "moderate",
            (
                "URL contains multiple recognizable "
                "brand references: "
                + ", ".join(
                    brand_tokens[:5]
                )
            ),
        )

    elif brand_count == 1:
        add(
            "brand_reference",
            3.0,
            "weak",
            (
                "URL contains a recognizable brand "
                "reference: "
                + brand_tokens[0]
            ),
        )

    # ------------------------------------------------
    # HTTP
    #
    # 35% of phishing sample used HTTP, but HTTP alone
    # is far too common to declare malicious.
    # ------------------------------------------------

    if not features.get(
        "uses_https",
        True,
    ):
        add(
            "plaintext_http",
            3.0,
            "weak",
            "URL does not use HTTPS.",
        )

    # ------------------------------------------------
    # CORROBORATION BONUSES
    #
    # This is the important part:
    # combinations matter more than individual features.
    # ------------------------------------------------

    finding_names = {
        finding.name
        for finding in findings
    }

    credential_structure = bool(
        {
            "sensitive_term",
            "multiple_sensitive_terms",
        }
        & finding_names
    )

    suspicious_hostname = bool(
        {
            "long_hostname",
            "very_long_hostname",
            "multiple_subdomains",
            "deep_subdomain_chain",
            "high_hostname_entropy",
            "very_high_hostname_entropy",
            "many_hyphens",
            "high_digit_ratio",
        }
        & finding_names
    )

    brand_structure = bool(
        {
            "brand_reference",
            "multiple_brand_tokens",
        }
        & finding_names
    )

    if (
        credential_structure
        and suspicious_hostname
    ):
        add(
            "credential_structure_corroboration",
            8.0,
            "strong",
            (
                "Credential-related terminology appears "
                "together with suspicious hostname structure."
            ),
        )

    if (
        brand_structure
        and suspicious_hostname
    ):
        add(
            "brand_structure_corroboration",
            8.0,
            "strong",
            (
                "Brand terminology appears together with "
                "suspicious hostname structure."
            ),
        )

    raw_score = sum(
        finding.points
        for finding in findings
    )

    score = round(
        min(
            raw_score,
            100.0,
        ),
        2,
    )

    strong_count = sum(
        finding.severity
        == "strong"
        for finding in findings
    )

    moderate_count = sum(
        finding.severity
        == "moderate"
        for finding in findings
    )

    confidence = min(
        0.95,
        0.35
        + strong_count * 0.15
        + moderate_count * 0.07
        + min(
            len(findings),
            8,
        ) * 0.025,
    )

    return {
        "score": score,
        "confidence": round(
            confidence,
            3,
        ),
        "finding_count": len(
            findings
        ),
        "strong_findings": (
            strong_count
        ),
        "moderate_findings": (
            moderate_count
        ),
        "findings": [
            {
                "name": finding.name,
                "points": finding.points,
                "severity": finding.severity,
                "reason": finding.reason,
            }
            for finding in findings
        ],
        "features": features,
    }
