from __future__ import annotations

import random
import re
from dataclasses import dataclass, asdict
from typing import Any

from app.global_entity_registry.database import (
    connection,
)


@dataclass
class ValidationCase:
    value: str
    expected_class: str

    source: str

    entity_name: str | None = None
    official_domain: str | None = None
    category: str | None = None
    country_code: str | None = None

    notes: str | None = None


def verified_domains(
    *,
    limit: int = 500,
) -> list[ValidationCase]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.domain,
                e.canonical_name,
                e.entity_type,
                e.country_code,
                COUNT(
                    DISTINCT es.source_name
                ) AS source_count

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            LEFT JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.active = 1

            GROUP BY
                d.id

            HAVING source_count >= 2

            ORDER BY
                source_count DESC,
                d.confidence DESC

            LIMIT ?
            """,
            (
                int(limit),
            ),
        ).fetchall()

    return [
        ValidationCase(
            value=(
                "https://"
                + str(
                    row["domain"]
                )
                + "/"
            ),
            expected_class="legitimate",
            source="registry_multi_source",
            entity_name=row[
                "canonical_name"
            ],
            official_domain=row[
                "domain"
            ],
            category=row[
                "entity_type"
            ],
            country_code=row[
                "country_code"
            ],
        )
        for row in rows
    ]


def supported_domains(
    *,
    limit: int = 250,
) -> list[ValidationCase]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.domain,
                e.canonical_name,
                e.entity_type,
                e.country_code,
                COUNT(
                    DISTINCT es.source_name
                ) AS source_count

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            LEFT JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.active = 1

            GROUP BY
                d.id

            HAVING source_count = 1

            ORDER BY
                d.confidence DESC

            LIMIT ?
            """,
            (
                int(limit),
            ),
        ).fetchall()

    return [
        ValidationCase(
            value=(
                "https://"
                + str(
                    row["domain"]
                )
                + "/"
            ),
            expected_class="legitimate",
            source="registry_single_source",
            entity_name=row[
                "canonical_name"
            ],
            official_domain=row[
                "domain"
            ],
            category=row[
                "entity_type"
            ],
            country_code=row[
                "country_code"
            ],
        )
        for row in rows
    ]


def registrable_label(
    domain: str,
) -> str:
    first = str(
        domain
    ).split(
        ".",
        1,
    )[0]

    first = re.sub(
        r"[^a-zA-Z0-9-]",
        "",
        first,
    )

    return (
        first
        or "brand"
    )


def mutate_label(
    label: str,
) -> list[str]:
    values = []

    cleaned = label.lower()

    substitutions = {
        "o": "0",
        "i": "1",
        "l": "1",
        "e": "3",
        "a": "4",
        "s": "5",
    }

    for index, char in enumerate(
        cleaned
    ):
        if char in substitutions:
            values.append(
                cleaned[:index]
                + substitutions[char]
                + cleaned[index + 1:]
            )

            break

    if len(
        cleaned
    ) >= 4:
        values.append(
            cleaned[:-1]
        )

    values.extend(
        [
            cleaned + "-login",
            cleaned + "-secure",
            "secure-" + cleaned,
            cleaned + "-verification",
            cleaned + "-account",
        ]
    )

    return list(
        dict.fromkeys(
            value
            for value in values
            if value
            and value != cleaned
        )
    )


def lookalike_cases(
    official_cases: list[ValidationCase],
    *,
    limit: int = 500,
) -> list[ValidationCase]:
    output = []

    suffixes = [
        ".example",
        ".test",
        ".invalid",
    ]

    for case in official_cases:
        if not case.official_domain:
            continue

        label = registrable_label(
            case.official_domain
        )

        variants = mutate_label(
            label
        )

        for index, variant in enumerate(
            variants
        ):
            suffix = suffixes[
                index
                % len(
                    suffixes
                )
            ]

            output.append(
                ValidationCase(
                    value=(
                        "https://"
                        + variant
                        + suffix
                        + "/"
                    ),
                    expected_class="lookalike",
                    source="synthetic_lookalike",
                    entity_name=case.entity_name,
                    official_domain=(
                        case.official_domain
                    ),
                    category=case.category,
                    country_code=(
                        case.country_code
                    ),
                    notes=(
                        "Synthetic non-resolving "
                        "impersonation candidate."
                    ),
                )
            )

            if len(
                output
            ) >= limit:
                return output

    return output


def deceptive_subdomain_cases(
    official_cases: list[ValidationCase],
    *,
    limit: int = 100,
) -> list[ValidationCase]:
    output = []

    for case in official_cases:
        if not case.official_domain:
            continue

        output.append(
            ValidationCase(
                value=(
                    "https://"
                    + case.official_domain
                    + ".attacker.example/"
                ),
                expected_class="lookalike",
                source="synthetic_deceptive_subdomain",
                entity_name=case.entity_name,
                official_domain=case.official_domain,
                category=case.category,
                country_code=case.country_code,
                notes=(
                    "Official domain appears as "
                    "a prefix under attacker.example."
                ),
            )
        )

        if len(
            output
        ) >= limit:
            break

    return output


def unknown_cases(
    *,
    count: int = 100,
) -> list[ValidationCase]:
    return [
        ValidationCase(
            value=(
                f"https://unknown-company-{index}.example/"
            ),
            expected_class="unknown",
            source="synthetic_unknown",
            notes=(
                "Unknown identity must remain neutral "
                "unless other malicious evidence exists."
            ),
        )
        for index in range(
            1,
            count + 1,
        )
    ]


def build_validation_corpus(
    *,
    verified_limit: int = 500,
    supported_limit: int = 250,
    lookalike_limit: int = 500,
    deceptive_limit: int = 100,
    unknown_count: int = 100,
) -> list[dict[str, Any]]:
    verified = verified_domains(
        limit=verified_limit
    )

    supported = supported_domains(
        limit=supported_limit
    )

    legitimate = [
        *verified,
        *supported,
    ]

    lookalikes = lookalike_cases(
        legitimate,
        limit=lookalike_limit,
    )

    deceptive = deceptive_subdomain_cases(
        legitimate,
        limit=deceptive_limit,
    )

    unknown = unknown_cases(
        count=unknown_count
    )

    corpus = [
        *legitimate,
        *lookalikes,
        *deceptive,
        *unknown,
    ]

    random.Random(
        42
    ).shuffle(
        corpus
    )

    return [
        asdict(
            item
        )
        for item in corpus
    ]
