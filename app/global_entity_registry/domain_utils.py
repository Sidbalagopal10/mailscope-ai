from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def normalize_hostname(
    value: str | None,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = (
            "https://"
            + cleaned
        )

    try:
        hostname = (
            urlsplit(
                cleaned
            ).hostname
            or ""
        )

    except ValueError:
        return ""

    hostname = (
        hostname
        .strip()
        .lower()
        .rstrip(".")
    )

    if hostname.startswith(
        "*."
    ):
        hostname = hostname[2:]

    if not hostname:
        return ""

    try:
        ipaddress.ip_address(
            hostname
        )

        return hostname

    except ValueError:
        pass

    try:
        return (
            hostname
            .encode("idna")
            .decode("ascii")
        )

    except UnicodeError:
        return ""


def is_exact_or_subdomain(
    hostname: str,
    official_domain: str,
) -> bool:
    host = normalize_hostname(
        hostname
    )

    official = normalize_hostname(
        official_domain
    )

    if not host or not official:
        return False

    return bool(
        host == official
        or host.endswith(
            "." + official
        )
    )


def canonical_identity_domain(
    value: str | None,
) -> str:
    """
    Normalize a hostname for organization identity.

    Cosmetic www. prefixes are collapsed:

        www.example.com
            -> example.com

    Meaningful subdomains remain intact:

        research.microsoft.com
            -> research.microsoft.com

        accounts.google.com
            -> accounts.google.com
    """

    hostname = normalize_hostname(
        value
    )

    if not hostname:
        return ""

    if hostname.startswith(
        "www."
    ):
        remainder = hostname[
            4:
        ]

        if remainder:
            return remainder

    return hostname
