from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse


BRAND_DOMAINS = {
    "adobe": {
        "adobe.com",
    },
    "amazon": {
        "amazon.com",
        "amazonaws.com",
    },
    "americanexpress": {
        "americanexpress.com",
    },
    "apple": {
        "apple.com",
        "icloud.com",
    },
    "bankofamerica": {
        "bankofamerica.com",
    },
    "capitalone": {
        "capitalone.com",
    },
    "chase": {
        "chase.com",
    },
    "citi": {
        "citi.com",
        "citibank.com",
    },
    "dropbox": {
        "dropbox.com",
    },
    "facebook": {
        "facebook.com",
        "facebookmail.com",
    },
    "github": {
        "github.com",
        "githubusercontent.com",
    },
    "google": {
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "gmail.com",
        "youtube.com",
    },
    "indeed": {
        "indeed.com",
    },
    "linkedin": {
        "linkedin.com",
        "lnkd.in",
    },
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "live.com",
        "outlook.com",
    },
    "netflix": {
        "netflix.com",
    },
    "paypal": {
        "paypal.com",
        "paypalobjects.com",
    },
    "stripe": {
        "stripe.com",
    },
    "wellsfargo": {
        "wellsfargo.com",
    },
    "workday": {
        "workday.com",
        "myworkdayjobs.com",
    },
}


TRACKING_AND_MARKETING_DOMAINS = {
    "braze.com",
    "branch.io",
    "campaign-archive.com",
    "click.email",
    "constantcontact.com",
    "doubleclick.net",
    "email-link.adtidy.org",
    "getresponse.com",
    "hubspotlinks.com",
    "iterable.com",
    "klaviyomail.com",
    "list-manage.com",
    "mailchi.mp",
    "mailchimp.com",
    "marketingautomation.services",
    "mandrillapp.com",
    "marketo.com",
    "marketo.net",
    "mktomail.com",
    "sendgrid.net",
    "sparkpostmail.com",
    "trk.klclick.com",
}


CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "2": "z",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "ı": "i",
        "і": "i",
        "Ι": "i",
        "ο": "o",
        "О": "o",
        "а": "a",
        "А": "a",
        "е": "e",
        "Е": "e",
        "р": "p",
        "Р": "p",
        "с": "c",
        "С": "c",
        "х": "x",
        "Х": "x",
    }
)


def normalize_hostname(
    hostname: str,
) -> str:
    normalized = str(
        hostname or ""
    ).strip().lower().rstrip(".")

    if normalized.startswith(
        "www."
    ):
        normalized = normalized[4:]

    return normalized


def registered_domain_approximation(
    hostname: str,
) -> str:
    """
    Local approximation suitable for lexical analysis.

    This deliberately avoids making network requests.
    """
    normalized = normalize_hostname(
        hostname
    )

    labels = [
        label
        for label in normalized.split(".")
        if label
    ]

    if len(labels) <= 2:
        return normalized

    common_second_level_suffixes = {
        "co.uk",
        "com.au",
        "co.in",
        "co.jp",
        "com.br",
        "com.mx",
        "co.nz",
    }

    last_two = ".".join(
        labels[-2:]
    )

    if last_two in (
        common_second_level_suffixes
    ) and len(labels) >= 3:
        return ".".join(
            labels[-3:]
        )

    return last_two


def base_domain_label(
    hostname: str,
) -> str:
    registered = (
        registered_domain_approximation(
            hostname
        )
    )

    return registered.split(
        ".",
        1,
    )[0]


def normalize_confusables(
    value: str,
) -> str:
    value = str(
        value or ""
    ).lower().translate(
        CONFUSABLE_TRANSLATION
    )

    return re.sub(
        r"[^a-z0-9]",
        "",
        value,
    )


def is_official_brand_domain(
    hostname: str,
    brand: str,
) -> bool:
    normalized_hostname = (
        normalize_hostname(
            hostname
        )
    )

    for official_domain in (
        BRAND_DOMAINS.get(
            brand,
            set(),
        )
    ):
        if (
            normalized_hostname
            == official_domain
            or normalized_hostname.endswith(
                f".{official_domain}"
            )
        ):
            return True

    return False


def is_tracking_domain(
    hostname: str,
) -> bool:
    normalized = normalize_hostname(
        hostname
    )

    return any(
        normalized == domain
        or normalized.endswith(
            f".{domain}"
        )
        for domain in (
            TRACKING_AND_MARKETING_DOMAINS
        )
    )


def brand_similarity(
    candidate: str,
    brand: str,
) -> float:
    normalized_candidate = (
        normalize_confusables(
            candidate
        )
    )

    normalized_brand = (
        normalize_confusables(
            brand
        )
    )

    if (
        not normalized_candidate
        or not normalized_brand
    ):
        return 0.0

    return SequenceMatcher(
        None,
        normalized_candidate,
        normalized_brand,
    ).ratio()


def inspect_brand_impersonation(
    url: str,
) -> dict[str, Any]:
    parsed = urlparse(
        str(url).strip()
    )

    hostname = normalize_hostname(
        parsed.hostname or ""
    )

    registered_domain = (
        registered_domain_approximation(
            hostname
        )
    )

    domain_label = base_domain_label(
        hostname
    )

    normalized_label = (
        normalize_confusables(
            domain_label
        )
    )

    full_hostname_tokens = [
        token
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            hostname,
        )
        if token
    ]

    findings = []

    for brand in BRAND_DOMAINS:
        if is_official_brand_domain(
            hostname,
            brand,
        ):
            continue

        similarity = brand_similarity(
            domain_label,
            brand,
        )

        normalized_brand = (
            normalize_confusables(
                brand
            )
        )

        exact_confusable_match = (
            normalized_label
            == normalized_brand
            and domain_label.lower()
            != brand.lower()
        )

        brand_in_untrusted_hostname = (
            normalized_brand
            in normalize_confusables(
                hostname
            )
        )

        token_similarity = max(
            (
                brand_similarity(
                    token,
                    brand,
                )
                for token in (
                    full_hostname_tokens
                )
            ),
            default=0.0,
        )

        strongest_similarity = max(
            similarity,
            token_similarity,
        )

        if exact_confusable_match:
            findings.append(
                {
                    "brand": brand,
                    "type": (
                        "confusable_substitution"
                    ),
                    "similarity": 1.0,
                    "severity": 38,
                    "reason": (
                        f"The registered domain closely "
                        f"imitates {brand} using visually "
                        "confusable characters."
                    ),
                }
            )

        elif strongest_similarity >= 0.88:
            findings.append(
                {
                    "brand": brand,
                    "type": (
                        "brand_typo"
                    ),
                    "similarity": round(
                        strongest_similarity,
                        4,
                    ),
                    "severity": 34,
                    "reason": (
                        f"The registered domain is a close "
                        f"misspelling of {brand}."
                    ),
                }
            )

        elif brand_in_untrusted_hostname:
            findings.append(
                {
                    "brand": brand,
                    "type": (
                        "brand_name_on_unofficial_domain"
                    ),
                    "similarity": round(
                        strongest_similarity,
                        4,
                    ),
                    "severity": 22,
                    "reason": (
                        f"The URL mentions {brand}, but the "
                        "registered domain is not an official "
                        f"{brand} domain."
                    ),
                }
            )

    findings.sort(
        key=lambda item: (
            item["severity"],
            item["similarity"],
        ),
        reverse=True,
    )

    strongest = (
        findings[0]
        if findings
        else None
    )

    return {
        "hostname": hostname,
        "registered_domain": (
            registered_domain
        ),
        "domain_label": domain_label,
        "tracking_domain": (
            is_tracking_domain(
                hostname
            )
        ),
        "impersonation_detected": bool(
            findings
        ),
        "strongest_finding": strongest,
        "findings": findings[:5],
    }


OFFICIAL_SAFE_DOMAINS = {
    "python.org",
    "pypi.org",
    "pythonhosted.org",
}


def is_known_official_domain(
    hostname: str,
) -> bool:
    """
    Return True for narrowly curated official domains.

    Unknown domains receive no penalty. This helper only
    supplies positive evidence for explicitly recognized
    official domains.
    """
    normalized = normalize_hostname(
        hostname
    )

    return any(
        normalized == official_domain
        or normalized.endswith(
            f".{official_domain}"
        )
        for official_domain in OFFICIAL_SAFE_DOMAINS
    )



# -------------------------------------------------------------------
# Conditional official-domain intelligence
# -------------------------------------------------------------------
#
# These domains provide positive evidence only when additional
# safeguards also pass. Unknown domains receive no penalty.
#
# Shared hosting, public email, redirect, CDN and multi-tenant domains
# are intentionally excluded.

CONDITIONALLY_TRUSTED_OFFICIAL_DOMAINS = {
    # Technology
    "adobe.com",
    "apple.com",
    "icloud.com",
    "github.com",
    "google.com",
    "microsoft.com",
    "office.com",
    "python.org",
    "pypi.org",
    "pythonhosted.org",

    # Professional and employment
    "linkedin.com",
    "indeed.com",
    "workday.com",

    # Commerce and payments
    "amazon.com",
    "paypal.com",
    "stripe.com",

    # Financial institutions
    "americanexpress.com",
    "bankofamerica.com",
    "capitalone.com",
    "chase.com",
    "citi.com",
    "citibank.com",
    "wellsfargo.com",

    # Media and services
    "dropbox.com",
    "facebook.com",
    "netflix.com",
}


def is_known_official_domain(
    hostname: str,
) -> bool:
    """
    Return True only for narrowly curated official domains.

    Absence from this set is neutral and never increases risk.
    Subdomains of an official domain are accepted.
    """
    normalized_hostname = normalize_hostname(
        hostname
    )

    return any(
        normalized_hostname == official_domain
        or normalized_hostname.endswith(
            f".{official_domain}"
        )
        for official_domain
        in CONDITIONALLY_TRUSTED_OFFICIAL_DOMAINS
    )
