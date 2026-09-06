from __future__ import annotations

import re
from typing import Any

from app.organization_graph.domain_resolver import (
    hostname_from_value,
    resolve_official_hostname,
)
from app.organization_graph.resolver import (
    resolve_brand_reference,
)


# These are structural / infrastructure words, NOT brands.
IGNORED_TOKENS = {
    "www",
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "dev",
    "app",
    "io",
    "co",

    "login",
    "signin",
    "secure",
    "security",
    "verify",
    "verification",
    "account",
    "auth",
    "portal",
    "support",
    "update",
    "service",
    "services",
    "online",
    "web",
    "site",

    "research",
    "group",
    "labs",
    "lab",
    "office",
    "international",
    "global",

    # Hosting infrastructure terms.
    "pages",
    "workers",
    "vercel",
    "netlify",
    "blogspot",
    "weebly",
    "githubusercontent",
}


def hostname_tokens(
    value: str,
) -> list[str]:
    hostname = hostname_from_value(
        value
    )

    if not hostname:
        return []

    tokens = re.findall(
        r"[a-z0-9]{3,}",
        hostname.replace(
            ".",
            "-"
        ),
    )

    return [
        token
        for token in tokens
        if (
            token
            not in IGNORED_TOKENS
            and not token.isdigit()
        )
    ]


def analyze_brand_identity(
    value: str,
    *,
    maximum_tokens: int = 10,
) -> dict[str, Any]:

    hostname = hostname_from_value(
        value
    )

    if not hostname:
        return {
            "hostname": "",
            "tokens": [],
            "official_matches": [],
            "organization_candidates": [],
            "impersonation_candidates": [],
            "possible_impersonation": False,
        }

    # -------------------------------------------------
    # RULE 1:
    # Resolve official-domain identity FIRST.
    # If the hostname is an exact official domain or
    # true subdomain, that relationship outranks lexical
    # token speculation.
    # -------------------------------------------------

    official_domain_matches = (
        resolve_official_hostname(
            value
        )
    )

    if official_domain_matches:
        return {
            "hostname": hostname,

            "tokens": hostname_tokens(
                value
            ),

            "official_matches": (
                official_domain_matches
            ),

            "organization_candidates": (
                official_domain_matches
            ),

            "impersonation_candidates": [],

            "possible_impersonation": False,

            "resolution_method": (
                "official_domain_relationship"
            ),
        }

    # -------------------------------------------------
    # RULE 2:
    # Only now perform lexical organization discovery.
    # -------------------------------------------------

    tokens = hostname_tokens(
        value
    )[
        :maximum_tokens
    ]

    candidates = []

    for token in tokens:
        matches = resolve_brand_reference(
            value=value,
            hostname=hostname,
            brand_text=token,
            limit=30,
        )

        for match in matches:
            score = float(
                match[
                    "brand_similarity"
                ]
            )

            if score < 0.78:
                continue

            candidates.append(
                {
                    "token": token,
                    **match,
                }
            )

    # -------------------------------------------------
    # Deduplicate regional / alias matches by node.
    # -------------------------------------------------

    deduplicated = {}

    for candidate in candidates:
        node_id = int(
            candidate[
                "node_id"
            ]
        )

        existing = deduplicated.get(
            node_id
        )

        if (
            existing is None
            or candidate[
                "brand_similarity"
            ]
            > existing[
                "brand_similarity"
            ]
        ):
            deduplicated[
                node_id
            ] = candidate

    ordered = sorted(
        deduplicated.values(),
        key=lambda item: (
            item[
                "brand_similarity"
            ],
            item[
                "matched_name_type"
            ]
            == "canonical",
        ),
        reverse=True,
    )

    impersonation_candidates = [
        item
        for item in ordered
        if (
            not item[
                "domain_belongs_to_organization"
            ]
            and item[
                "brand_similarity"
            ]
            >= 0.90
        )
    ]

    return {
        "hostname": hostname,

        "tokens": tokens,

        "official_matches": [],

        "organization_candidates": (
            ordered
        ),

        "impersonation_candidates": (
            impersonation_candidates
        ),

        "possible_impersonation": bool(
            impersonation_candidates
        ),

        "resolution_method": (
            "lexical_organization_graph"
        ),
    }
