from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.organization_intelligence import store


DATABASE_PATH = Path(
    "data/brand_intelligence/global_brand_index.db"
)

GENERIC_TERMS = {
    "academic",
    "administration",
    "admissions",
    "advanced",
    "applied",
    "campus",
    "community",
    "county",
    "district",
    "education",
    "engineering",
    "faculty",
    "learning",
    "medical",
    "municipal",
    "polytechnic",
    "program",
    "public",
    "research",
    "science",
    "student",
    "studies",
    "academy",
    "association",
    "bank",
    "business",
    "center",
    "centre",
    "city",
    "college",
    "company",
    "corporation",
    "department",
    "foundation",
    "global",
    "government",
    "group",
    "health",
    "hospital",
    "institute",
    "international",
    "limited",
    "ministry",
    "national",
    "office",
    "organization",
    "school",
    "services",
    "solutions",
    "state",
    "systems",
    "technology",
    "university",
}

CORPORATE_SUFFIXES = {
    "ag",
    "corp",
    "corporation",
    "gmbh",
    "inc",
    "incorporated",
    "limited",
    "llc",
    "ltd",
    "plc",
    "pty",
    "sa",
}

BUILTIN_BRANDS = [
    {
        "brand_name": "Apple",
        "aliases": ["apple", "icloud"],
        "domains": ["apple.com", "icloud.com"],
    },
    {
        "brand_name": "Google",
        "aliases": ["google", "gmail", "youtube"],
        "domains": ["google.com", "gmail.com", "youtube.com"],
    },
    {
        "brand_name": "Microsoft",
        "aliases": [
            "microsoft",
            "office",
            "outlook",
            "onedrive",
        ],
        "domains": [
            "microsoft.com",
            "office.com",
            "live.com",
            "outlook.com",
        ],
    },
    {
        "brand_name": "LinkedIn",
        "aliases": ["linkedin"],
        "domains": ["linkedin.com"],
    },
    {
        "brand_name": "Amazon",
        "aliases": ["amazon", "aws"],
        "domains": [
            "amazon.com",
            "amazon.in",
            "amazon.co.uk",
            "aws.amazon.com",
        ],
    },
    {
        "brand_name": "PayPal",
        "aliases": ["paypal"],
        "domains": ["paypal.com"],
    },
    {
        "brand_name": "Netflix",
        "aliases": ["netflix"],
        "domains": ["netflix.com"],
    },
    {
        "brand_name": "GitHub",
        "aliases": ["github"],
        "domains": ["github.com"],
    },
]


class BrandIntelligenceError(Exception):
    pass


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS brands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand_name TEXT NOT NULL,
                normalized_brand TEXT NOT NULL,
                entity_type TEXT,
                country_code TEXT,
                organization_id INTEGER,
                source TEXT NOT NULL,
                UNIQUE(
                    normalized_brand,
                    organization_id,
                    source
                )
            );

            CREATE TABLE IF NOT EXISTS brand_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand_id INTEGER NOT NULL,
                alias TEXT NOT NULL,
                normalized_alias TEXT NOT NULL,
                alias_type TEXT NOT NULL,
                FOREIGN KEY(brand_id)
                    REFERENCES brands(id)
                    ON DELETE CASCADE,
                UNIQUE(
                    brand_id,
                    normalized_alias
                )
            );

            CREATE TABLE IF NOT EXISTS brand_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                identity_confidence REAL NOT NULL DEFAULT 0,
                identity_state TEXT,
                security_state TEXT,
                FOREIGN KEY(brand_id)
                    REFERENCES brands(id)
                    ON DELETE CASCADE,
                UNIQUE(
                    brand_id,
                    domain
                )
            );

            CREATE INDEX IF NOT EXISTS
            idx_brand_normalized
            ON brands(normalized_brand);

            CREATE INDEX IF NOT EXISTS
            idx_alias_normalized
            ON brand_aliases(normalized_alias);

            CREATE INDEX IF NOT EXISTS
            idx_brand_domain
            ON brand_domains(domain);
            """
        )

        connection.commit()


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize(
        "NFKD",
        str(value or ""),
    )

    ascii_text = normalized.encode(
        "ascii",
        errors="ignore",
    ).decode(
        "ascii",
    )

    return re.sub(
        r"[^a-z0-9]+",
        "",
        ascii_text.lower(),
    )


def normalize_domain(value: str) -> str:
    cleaned = str(
        value or ""
    ).strip().lower()

    if "://" in cleaned:
        cleaned = (
            urlparse(cleaned).hostname
            or ""
        )

    cleaned = (
        cleaned.split("/")[0]
        .split(":")[0]
        .rstrip(".")
    )

    if cleaned.startswith("www."):
        cleaned = cleaned[4:]

    if not cleaned or "." not in cleaned:
        raise BrandIntelligenceError(
            "Enter a complete domain."
        )

    return cleaned.encode(
        "idna"
    ).decode(
        "ascii"
    )


def domain_tokens(domain: str) -> list[str]:
    hostname = normalize_domain(
        domain
    )

    return [
        normalize_text(token)
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            hostname,
        )
        if normalize_text(token)
    ]


def organization_aliases(
    legal_name: str,
    domain: str,
) -> set[str]:
    """
    Generate conservative aliases.

    Organization-registry entries are identity records, not
    automatically globally recognizable brands. Avoid turning
    ordinary words such as applied, learning, public, state or
    college into protected brand aliases.
    """
    raw_words = [
        normalize_text(word)
        for word in re.split(
            r"[^a-zA-Z0-9]+",
            legal_name,
        )
    ]

    meaningful_words = [
        word
        for word in raw_words
        if (
            len(word) >= 5
            and word not in GENERIC_TERMS
            and word not in CORPORATE_SUFFIXES
        )
    ]

    aliases: set[str] = set()

    # Do not add every individual word. Single words from long
    # organization names are a major false-positive source.
    if len(meaningful_words) == 1:
        aliases.add(
            meaningful_words[0]
        )

    combined = "".join(
        meaningful_words
    )

    if len(combined) >= 7:
        aliases.add(
            combined
        )

    normalized_name = normalize_text(
        legal_name
    )

    if len(normalized_name) >= 7:
        aliases.add(
            normalized_name
        )

    first_label = normalize_text(
        normalize_domain(
            domain
        ).split(".")[0]
    )

    # Domain labels are useful only when sufficiently distinctive.
    if (
        len(first_label) >= 6
        and first_label not in GENERIC_TERMS
    ):
        aliases.add(
            first_label
        )

    return {
        alias
        for alias in aliases
        if (
            len(alias) >= 5
            and alias not in GENERIC_TERMS
            and alias not in CORPORATE_SUFFIXES
        )
    }


def upsert_brand(
    *,
    brand_name: str,
    aliases: set[str],
    domains: list[str],
    entity_type: str | None,
    country_code: str | None,
    organization_id: int | None,
    source: str,
    identity_confidence: float = 0.0,
    identity_state: str | None = None,
    security_state: str | None = None,
) -> int:
    initialize_database()

    normalized_brand = normalize_text(
        brand_name
    )

    if len(normalized_brand) < 4:
        raise BrandIntelligenceError(
            "Brand name is too short."
        )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO brands (
                brand_name,
                normalized_brand,
                entity_type,
                country_code,
                organization_id,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                brand_name,
                normalized_brand,
                entity_type,
                country_code,
                organization_id,
                source,
            ),
        )

        row = connection.execute(
            """
            SELECT id
            FROM brands
            WHERE normalized_brand = ?
              AND organization_id IS ?
              AND source = ?
            """,
            (
                normalized_brand,
                organization_id,
                source,
            ),
        ).fetchone()

        if row is None:
            raise BrandIntelligenceError(
                "Brand record could not be saved."
            )

        brand_id = int(
            row["id"]
        )

        all_aliases = {
            normalized_brand,
            *{
                normalize_text(alias)
                for alias in aliases
            },
        }

        for alias in all_aliases:
            if (
                len(alias) < 4
                or alias in GENERIC_TERMS
            ):
                continue

            connection.execute(
                """
                INSERT OR IGNORE INTO brand_aliases (
                    brand_id,
                    alias,
                    normalized_alias,
                    alias_type
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    brand_id,
                    alias,
                    alias,
                    (
                        "canonical"
                        if alias
                        == normalized_brand
                        else "derived"
                    ),
                ),
            )

        for domain in domains:
            try:
                normalized_domain = (
                    normalize_domain(
                        domain
                    )
                )
            except Exception:
                continue

            connection.execute(
                """
                INSERT OR REPLACE INTO brand_domains (
                    brand_id,
                    domain,
                    identity_confidence,
                    identity_state,
                    security_state
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    brand_id,
                    normalized_domain,
                    float(
                        identity_confidence
                    ),
                    identity_state,
                    security_state,
                ),
            )

        connection.commit()

    return brand_id


def build_global_brand_index() -> dict[str, Any]:
    initialize_database()

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM brand_domains"
        )
        connection.execute(
            "DELETE FROM brand_aliases"
        )
        connection.execute(
            "DELETE FROM brands"
        )
        connection.commit()

    builtin_count = 0

    for entry in BUILTIN_BRANDS:
        upsert_brand(
            brand_name=entry[
                "brand_name"
            ],
            aliases=set(
                entry["aliases"]
            ),
            domains=entry[
                "domains"
            ],
            entity_type="corporation",
            country_code=None,
            organization_id=None,
            source="builtin",
            identity_confidence=98,
            identity_state=(
                "VERIFIED_ESTABLISHED"
            ),
            security_state="NEUTRAL",
        )

        builtin_count += 1

    imported_organizations = 0
    imported_domains = 0
    failed = 0

    store.initialize_database()

    with store.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                od.domain,
                od.identity_confidence,
                od.identity_state,
                od.security_state,
                o.id AS organization_id,
                o.legal_name,
                o.entity_type,
                o.country_code
            FROM organization_domains od
            JOIN organizations o
              ON o.id = od.organization_id
            ORDER BY o.id
            """
        ).fetchall()

    grouped: dict[int, dict[str, Any]] = {}

    for row in rows:
        organization_id = int(
            row["organization_id"]
        )

        item = grouped.setdefault(
            organization_id,
            {
                "legal_name": row[
                    "legal_name"
                ],
                "entity_type": row[
                    "entity_type"
                ],
                "country_code": row[
                    "country_code"
                ],
                "domains": [],
                "identity_confidence": 0.0,
                "identity_state": row[
                    "identity_state"
                ],
                "security_state": row[
                    "security_state"
                ],
            },
        )

        item["domains"].append(
            row["domain"]
        )

        item[
            "identity_confidence"
        ] = max(
            float(
                item[
                    "identity_confidence"
                ]
            ),
            float(
                row[
                    "identity_confidence"
                ]
                or 0
            ),
        )

    for organization_id, item in grouped.items():
        try:
            aliases = set()

            for domain in item[
                "domains"
            ]:
                aliases.update(
                    organization_aliases(
                        item[
                            "legal_name"
                        ],
                        domain,
                    )
                )

            if not aliases:
                continue

            upsert_brand(
                brand_name=item[
                    "legal_name"
                ],
                aliases=aliases,
                domains=item[
                    "domains"
                ],
                entity_type=item[
                    "entity_type"
                ],
                country_code=item[
                    "country_code"
                ],
                organization_id=(
                    organization_id
                ),
                source=(
                    "organization_intelligence"
                ),
                identity_confidence=item[
                    "identity_confidence"
                ],
                identity_state=item[
                    "identity_state"
                ],
                security_state=item[
                    "security_state"
                ],
            )

            imported_organizations += 1
            imported_domains += len(
                item["domains"]
            )

        except Exception:
            failed += 1

    return {
        "builtin_brands": builtin_count,
        "imported_organizations": (
            imported_organizations
        ),
        "imported_domains": (
            imported_domains
        ),
        "failed": failed,
        "summary": get_summary(),
    }


def levenshtein_distance(
    first: str,
    second: str,
) -> int:
    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous = list(
        range(
            len(second) + 1
        )
    )

    for first_index, first_char in enumerate(
        first,
        start=1,
    ):
        current = [
            first_index
        ]

        for second_index, second_char in enumerate(
            second,
            start=1,
        ):
            insertion = (
                current[
                    second_index - 1
                ]
                + 1
            )

            deletion = (
                previous[
                    second_index
                ]
                + 1
            )

            substitution = (
                previous[
                    second_index - 1
                ]
                + (
                    first_char
                    != second_char
                )
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous = current

    return previous[-1]


def confusable_normalize(
    value: str,
) -> str:
    translation = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "8": "b",
        }
    )

    return normalize_text(
        value
    ).translate(
        translation
    )


def is_official_domain(
    hostname: str,
    official_domain: str,
) -> bool:
    return (
        hostname == official_domain
        or hostname.endswith(
            f".{official_domain}"
        )
    )


def load_alias_candidates(
    token: str,
) -> list[dict[str, Any]]:
    normalized_token = confusable_normalize(
        token
    )

    if len(normalized_token) < 4:
        return []

    first_character = normalized_token[0]

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                b.id AS brand_id,
                b.brand_name,
                b.normalized_brand,
                b.entity_type,
                b.country_code,
                b.source,
                ba.normalized_alias
            FROM brand_aliases ba
            JOIN brands b
              ON b.id = ba.brand_id
            WHERE substr(
                ba.normalized_alias,
                1,
                1
            ) = ?
              AND length(
                ba.normalized_alias
            ) BETWEEN ? AND ?
            LIMIT 5000
            """,
            (
                first_character,
                max(
                    4,
                    len(
                        normalized_token
                    )
                    - 3,
                ),
                len(
                    normalized_token
                )
                + 3,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def brand_domains(
    brand_id: int,
) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM brand_domains
            WHERE brand_id = ?
            ORDER BY
                identity_confidence DESC,
                domain
            """,
            (
                int(
                    brand_id
                ),
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def resolve_official_domain_owner(
    hostname: str,
) -> dict[str, Any] | None:
    """
    Resolve the most specific official domain before performing
    fuzzy matching. An exact or parent-domain match overrides
    unrelated similarity candidates.
    """
    normalized_hostname = normalize_domain(
        hostname
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                b.id AS brand_id,
                b.brand_name,
                b.normalized_brand,
                b.entity_type,
                b.country_code,
                b.source,
                bd.domain,
                bd.identity_confidence,
                bd.identity_state,
                bd.security_state
            FROM brand_domains bd
            JOIN brands b
              ON b.id = bd.brand_id
            """
        ).fetchall()

    matches = [
        dict(row)
        for row in rows
        if (
            normalized_hostname
            == row["domain"]
            or normalized_hostname.endswith(
                f".{row['domain']}"
            )
        )
    ]

    if not matches:
        return None

    matches.sort(
        key=lambda item: (
            len(
                item["domain"]
            ),
            float(
                item.get(
                    "identity_confidence",
                    0,
                )
                or 0
            ),
            1
            if item.get(
                "source"
            )
            == "builtin"
            else 0,
        ),
        reverse=True,
    )

    return matches[0]


def analyze_brand_impersonation(
    value: str,
) -> dict[str, Any]:
    initialize_database()

    hostname = normalize_domain(
        value
    )

    official_owner = resolve_official_domain_owner(
        hostname
    )

    if official_owner is not None:
        return {
            "hostname": hostname,
            "official_domain_match": True,
            "official_owner": official_owner,
            "impersonation_detected": False,
            "strongest_finding": None,
            "findings": [],
            "risk_adjustment": 0.0,
            "reason": (
                "The hostname matches a recorded official "
                "domain or its subdomain."
            ),
            "important_limitations": [
                (
                    "An official domain can still be compromised."
                ),
                (
                    "This result confirms domain identity, not "
                    "the safety of every page or message."
                ),
            ],
        }

    tokens = domain_tokens(
        hostname
    )

    findings = []

    for token in tokens:
        normalized_token = (
            confusable_normalize(
                token
            )
        )

        if (
            len(normalized_token) < 4
            or normalized_token
            in GENERIC_TERMS
        ):
            continue

        for candidate in load_alias_candidates(
            normalized_token
        ):
            alias = confusable_normalize(
                candidate[
                    "normalized_alias"
                ]
            )

            if (
                len(alias) < 4
                or alias in GENERIC_TERMS
            ):
                continue

            official_domains = brand_domains(
                candidate[
                    "brand_id"
                ]
            )

            official_match = any(
                is_official_domain(
                    hostname,
                    record["domain"],
                )
                for record
                in official_domains
            )

            if official_match:
                continue

            distance = levenshtein_distance(
                normalized_token,
                alias,
            )

            similarity = SequenceMatcher(
                None,
                normalized_token,
                alias,
            ).ratio()

            exact_unofficial = (
                normalized_token == alias
            )

            typo_match = (
                not exact_unofficial
                and similarity >= 0.82
                and distance
                <= (
                    1
                    if len(alias) <= 6
                    else 2
                )
            )

            if not (
                exact_unofficial
                or typo_match
            ):
                continue

            if exact_unofficial:
                finding_type = (
                    "brand_on_unofficial_domain"
                )
                severity = 28

            else:
                finding_type = (
                    "typosquatting"
                )
                severity = min(
                    42,
                    30
                    + max(
                        0,
                        2 - distance
                    )
                    * 4,
                )

            findings.append(
                {
                    "brand_id": candidate[
                        "brand_id"
                    ],
                    "brand_name": candidate[
                        "brand_name"
                    ],
                    "matched_alias": candidate[
                        "normalized_alias"
                    ],
                    "hostname_token": token,
                    "type": finding_type,
                    "similarity": round(
                        similarity,
                        4,
                    ),
                    "edit_distance": distance,
                    "severity": severity,
                    "official_domains": [
                        item["domain"]
                        for item
                        in official_domains[
                            :20
                        ]
                    ],
                    "entity_type": candidate[
                        "entity_type"
                    ],
                    "country_code": candidate[
                        "country_code"
                    ],
                    "source": candidate[
                        "source"
                    ],
                    "reason": (
                        f"'{token}' resembles the "
                        f"brand '{candidate['brand_name']}' "
                        "but the hostname is not one of its "
                        "recorded official domains."
                    ),
                }
            )

    unique_findings = {}

    for finding in findings:
        key = (
            finding["brand_id"],
            finding["hostname_token"],
            finding["type"],
        )

        existing = unique_findings.get(
            key
        )

        if (
            existing is None
            or finding["severity"]
            > existing["severity"]
        ):
            unique_findings[
                key
            ] = finding

    ordered = sorted(
        unique_findings.values(),
        key=lambda item: (
            1
            if item.get(
                "source"
            )
            == "builtin"
            else 0,
            item["severity"],
            item["similarity"],
            -item["edit_distance"],
        ),
        reverse=True,
    )

    strongest = (
        ordered[0]
        if ordered
        else None
    )

    return {
        "hostname": hostname,
        "impersonation_detected": bool(
            ordered
        ),
        "strongest_finding": strongest,
        "findings": ordered[:20],
        "risk_adjustment": (
            float(
                strongest[
                    "severity"
                ]
            )
            if strongest
            else 0.0
        ),
        "important_limitations": [
            (
                "A name similarity match requires analyst "
                "or corroborating evidence before enforcement."
            ),
            (
                "Official domains can still be compromised."
            ),
            (
                "Unknown brands and newly established "
                "organizations may not yet be indexed."
            ),
        ],
    }


def get_summary() -> dict[str, Any]:
    initialize_database()

    with get_connection() as connection:
        brands = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM brands
            """
        ).fetchone()["count"]

        aliases = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM brand_aliases
            """
        ).fetchone()["count"]

        domains = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM brand_domains
            """
        ).fetchone()["count"]

        countries = connection.execute(
            """
            SELECT COUNT(
                DISTINCT country_code
            ) AS count
            FROM brands
            WHERE country_code IS NOT NULL
              AND country_code != ''
            """
        ).fetchone()["count"]

    return {
        "brands": int(
            brands
        ),
        "aliases": int(
            aliases
        ),
        "official_domains": int(
            domains
        ),
        "countries": int(
            countries
        ),
    }
