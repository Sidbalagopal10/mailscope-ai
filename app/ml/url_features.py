from __future__ import annotations

import ipaddress
import re
from typing import Dict, Union
from urllib.parse import (
    parse_qs,
    unquote,
    urlparse,
)

from app.detection.brand_intelligence import (
    inspect_brand_impersonation,
    is_tracking_domain,
    normalize_hostname,
    registered_domain_approximation,
)


FeatureValue = Union[int, float]


HIGH_SIGNAL_KEYWORDS = {
    "credential",
    "password",
    "signin",
    "login",
    "otp",
    "unlock",
    "suspend",
    "verification",
    "verify",
    "wallet",
}


LOW_SIGNAL_BUSINESS_WORDS = {
    "account",
    "alert",
    "application",
    "auth",
    "bank",
    "billing",
    "career",
    "confirm",
    "invoice",
    "job",
    "payment",
    "recover",
    "secure",
    "security",
    "statement",
    "support",
    "update",
}


URL_SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}


SPECIAL_CHARACTERS = {
    "@": "count_at_symbols",
    "-": "count_hyphens",
    "_": "count_underscores",
    "=": "count_equals",
    "?": "count_question_marks",
    "&": "count_ampersands",
    "%": "count_percent_symbols",
    ".": "count_dots",
}


def hostname_is_ip_address(
    hostname: str,
) -> bool:
    try:
        ipaddress.ip_address(
            hostname
        )
        return True
    except ValueError:
        return False


def count_subdomains(
    hostname: str,
) -> int:
    if (
        not hostname
        or hostname_is_ip_address(
            hostname
        )
    ):
        return 0

    registered = (
        registered_domain_approximation(
            hostname
        )
    )

    hostname_labels = hostname.split(
        "."
    )

    registered_labels = (
        registered.split(".")
    )

    return max(
        len(hostname_labels)
        - len(registered_labels),
        0,
    )


def count_keywords(
    value: str,
    keywords: set[str],
) -> int:
    lowercase_value = value.lower()

    return sum(
        1
        for keyword in keywords
        if keyword in lowercase_value
    )


def has_suspicious_port(
    parsed_url,
) -> bool:
    try:
        port = parsed_url.port
    except ValueError:
        return True

    if port is None:
        return False

    if (
        parsed_url.scheme == "http"
        and port == 80
    ):
        return False

    if (
        parsed_url.scheme == "https"
        and port == 443
    ):
        return False

    return True


def extract_url_features(
    url: str,
) -> Dict[str, FeatureValue]:
    cleaned_url = str(
        url or ""
    ).strip()

    parsed_url = urlparse(
        cleaned_url
    )

    hostname = normalize_hostname(
        parsed_url.hostname or ""
    )

    registered_domain = (
        registered_domain_approximation(
            hostname
        )
    )

    path = parsed_url.path or ""
    query = parsed_url.query or ""

    decoded_path_and_query = unquote(
        f"{path}?{query}"
    )

    keyword_search_text = (
        f"{hostname} "
        f"{decoded_path_and_query}"
    )

    query_parameters = parse_qs(
        query,
        keep_blank_values=True,
    )

    brand_result = (
        inspect_brand_impersonation(
            cleaned_url
        )
    )

    strongest_brand_finding = (
        brand_result.get(
            "strongest_finding"
        )
        or {}
    )

    lowercase_url = (
        cleaned_url.lower()
    )

    features: Dict[
        str,
        FeatureValue,
    ] = {
        "url_length": len(
            cleaned_url
        ),
        "hostname_length": len(
            hostname
        ),
        "registered_domain_length": len(
            registered_domain
        ),
        "path_length": len(
            path
        ),
        "query_length": len(
            query
        ),
        "count_digits": sum(
            character.isdigit()
            for character in (
                cleaned_url
            )
        ),
        "count_letters": sum(
            character.isalpha()
            for character in (
                cleaned_url
            )
        ),
        "count_subdomains": (
            count_subdomains(
                hostname
            )
        ),
        "count_path_segments": len(
            [
                segment
                for segment in (
                    path.split("/")
                )
                if segment
            ]
        ),
        "count_query_parameters": len(
            query_parameters
        ),
        "uses_https": int(
            parsed_url.scheme.lower()
            == "https"
        ),
        "uses_http": int(
            parsed_url.scheme.lower()
            == "http"
        ),
        "hostname_is_ip": int(
            hostname_is_ip_address(
                hostname
            )
        ),
        "uses_url_shortener": int(
            hostname in URL_SHORTENERS
        ),
        "is_tracking_domain": int(
            is_tracking_domain(
                hostname
            )
        ),
        "contains_punycode": int(
            "xn--" in hostname
        ),
        "contains_encoded_characters": int(
            bool(
                re.search(
                    r"%[0-9a-fA-F]{2}",
                    cleaned_url,
                )
            )
        ),
        "contains_double_slash_in_path": int(
            "//" in path
        ),
        "contains_suspicious_port": int(
            has_suspicious_port(
                parsed_url
            )
        ),
        "count_high_signal_keywords": (
            count_keywords(
                keyword_search_text,
                HIGH_SIGNAL_KEYWORDS,
            )
        ),
        "count_business_keywords": (
            count_keywords(
                keyword_search_text,
                LOW_SIGNAL_BUSINESS_WORDS,
            )
        ),
        # Retained for compatibility with older scripts.
        "count_suspicious_keywords": (
            count_keywords(
                keyword_search_text,
                HIGH_SIGNAL_KEYWORDS
                | LOW_SIGNAL_BUSINESS_WORDS,
            )
        ),
        "brand_impersonation": int(
            brand_result.get(
                "impersonation_detected",
                False,
            )
        ),
        "brand_similarity": float(
            strongest_brand_finding.get(
                "similarity",
                0.0,
            )
            or 0.0
        ),
        "brand_risk_severity": int(
            strongest_brand_finding.get(
                "severity",
                0,
            )
            or 0
        ),
    }

    for (
        character,
        feature_name,
    ) in SPECIAL_CHARACTERS.items():
        features[feature_name] = (
            cleaned_url.count(
                character
            )
        )

    total_characters = max(
        len(cleaned_url),
        1,
    )

    features["digit_ratio"] = round(
        features["count_digits"]
        / total_characters,
        4,
    )

    features[
        "special_character_ratio"
    ] = round(
        sum(
            cleaned_url.count(
                character
            )
            for character in (
                SPECIAL_CHARACTERS
            )
        )
        / total_characters,
        4,
    )

    features[
        "query_to_url_ratio"
    ] = round(
        len(query)
        / total_characters,
        4,
    )

    return features
