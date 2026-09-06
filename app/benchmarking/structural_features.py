from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import (
    parse_qsl,
    unquote,
    urlsplit,
)


SENSITIVE_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "passwd",
    "account",
    "auth",
    "authenticate",
    "credential",
    "credentials",
    "secure",
    "security",
    "update",
    "confirm",
    "wallet",
    "billing",
    "payment",
    "invoice",
    "recover",
    "recovery",
    "reset",
    "unlock",
    "sso",
    "oauth",
    "session",
}


COMMON_BRANDS = {
    "google",
    "gmail",
    "microsoft",
    "office365",
    "outlook",
    "apple",
    "icloud",
    "amazon",
    "paypal",
    "github",
    "linkedin",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "dropbox",
    "docusign",
    "adobe",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "coinbase",
}


HEX_PATTERN = re.compile(
    r"^[0-9a-f]{12,}$",
    re.IGNORECASE,
)


def safe_ratio(
    numerator: int,
    denominator: int,
) -> float:
    if denominator <= 0:
        return 0.0

    return numerator / denominator


def shannon_entropy(
    value: str,
) -> float:
    if not value:
        return 0.0

    counts = Counter(
        value
    )

    length = len(
        value
    )

    entropy = 0.0

    for count in counts.values():
        probability = (
            count / length
        )

        entropy -= (
            probability
            * math.log2(
                probability
            )
        )

    return round(
        entropy,
        4,
    )


def is_ip_hostname(
    hostname: str,
) -> bool:
    try:
        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:
        return False


def extract_structural_features(
    value: str,
) -> dict[str, Any]:
    raw = str(
        value or ""
    ).strip()

    if not raw:
        return {}

    if "://" not in raw:
        raw = (
            "https://"
            + raw
        )

    try:
        parsed = urlsplit(
            raw
        )

    except ValueError:
        return {}

    hostname = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    hostname_length = len(
        hostname
    )

    url_length = len(
        raw
    )

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    alpha_count = sum(
        character.isalpha()
        for character in hostname
    )

    hyphen_count = hostname.count(
        "-"
    )

    underscore_count = hostname.count(
        "_"
    )

    path = unquote(
        parsed.path or ""
    ).lower()

    query = unquote(
        parsed.query or ""
    ).lower()

    combined_text = (
        hostname
        + " "
        + path
        + " "
        + query
    )

    sensitive_matches = sorted(
        term
        for term in SENSITIVE_TERMS
        if term in combined_text
    )

    brand_matches = sorted(
        brand
        for brand in COMMON_BRANDS
        if brand in combined_text
    )

    query_pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    longest_label = max(
        (
            len(label)
            for label in labels
        ),
        default=0,
    )

    hex_like_labels = sum(
        1
        for label in labels
        if HEX_PATTERN.match(
            label
        )
    )

    encoded_tokens = (
        raw.count("%")
    )

    repeated_separator = bool(
        "--" in hostname
        or ".." in hostname
        or "//" in (
            parsed.path
            or ""
        )
    )

    non_standard_port = bool(
        parsed.port
        and not (
            (
                parsed.scheme.lower()
                == "http"
                and parsed.port == 80
            )
            or (
                parsed.scheme.lower()
                == "https"
                and parsed.port == 443
            )
        )
    )

    return {
        "url_length": (
            url_length
        ),

        "hostname_length": (
            hostname_length
        ),

        "hostname_entropy": (
            shannon_entropy(
                hostname
            )
        ),

        "url_entropy": (
            shannon_entropy(
                raw.lower()
            )
        ),

        "label_count": len(
            labels
        ),

        # Approximate depth. PSL-aware depth comes later.
        "subdomain_depth": max(
            0,
            len(labels) - 2,
        ),

        "longest_label_length": (
            longest_label
        ),

        "digit_count": (
            digit_count
        ),

        "digit_ratio": round(
            safe_ratio(
                digit_count,
                hostname_length,
            ),
            4,
        ),

        "alpha_ratio": round(
            safe_ratio(
                alpha_count,
                hostname_length,
            ),
            4,
        ),

        "hyphen_count": (
            hyphen_count
        ),

        "underscore_count": (
            underscore_count
        ),

        "contains_punycode": (
            "xn--"
            in hostname
        ),

        "hostname_is_ip": (
            is_ip_hostname(
                hostname
            )
        ),

        "contains_at_symbol": (
            "@"
            in raw
        ),

        "query_parameter_count": len(
            query_pairs
        ),

        "encoded_token_count": (
            encoded_tokens
        ),

        "sensitive_term_count": len(
            sensitive_matches
        ),

        "brand_token_count": len(
            brand_matches
        ),

        "hex_like_label_count": (
            hex_like_labels
        ),

        "repeated_separator": (
            repeated_separator
        ),

        "non_standard_port": (
            non_standard_port
        ),

        "uses_https": (
            parsed.scheme.lower()
            == "https"
        ),

        "path_length": len(
            parsed.path or ""
        ),

        "query_length": len(
            parsed.query or ""
        ),

        "sensitive_terms": (
            sensitive_matches
        ),

        "brand_tokens": (
            brand_matches
        ),

        "hostname": (
            hostname
        ),
    }
