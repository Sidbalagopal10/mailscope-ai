from __future__ import annotations

import ipaddress

import tldextract

from app.global_entity_registry.domain_utils import (
    normalize_hostname,
)


# tldextract uses the Public Suffix List and maintains a local cache.
_EXTRACTOR = tldextract.TLDExtract(
    include_psl_private_domains=False,
)


def registrable_domain(
    value: str | None,
) -> str:
    """
    Return the registrable domain according to the Public Suffix List.

    Examples:
        www.google.com     -> google.com
        news.bbc.co.uk     -> bbc.co.uk
        www.isro.gov.in    -> isro.gov.in

    Unknown/private development suffixes fall back to the hostname.
    """
    hostname = normalize_hostname(
        value
    )

    if not hostname:
        return ""

    try:
        ipaddress.ip_address(
            hostname
        )
        return hostname

    except ValueError:
        pass

    extracted = _EXTRACTOR(
        hostname
    )

    result = (
        extracted.top_domain_under_public_suffix
        or ""
    ).strip().lower()

    return (
        result
        or hostname
    )


def domain_relationship(
    hostname: str,
    official_hostname: str,
) -> str:
    host = normalize_hostname(
        hostname
    )

    official = normalize_hostname(
        official_hostname
    )

    if not host or not official:
        return "unrelated"

    if host == official:
        return "exact"

    if host.endswith(
        "." + official
    ):
        return "true_subdomain"

    return "unrelated"
