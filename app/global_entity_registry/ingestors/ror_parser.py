from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
    normalize_hostname,
)
from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)


TYPE_MAP = {
    "education": "education",
    "healthcare": "healthcare",
    "company": "company",
    "archive": "archive",
    "nonprofit": "nonprofit",
    "government": "government",
    "facility": "facility",
    "funder": "funder",
    "other": "other",
}


def display_name(
    record: dict[str, Any],
) -> str:
    names = record.get(
        "names",
        [],
    )

    if not isinstance(
        names,
        list,
    ):
        return ""

    for item in names:
        if not isinstance(
            item,
            dict,
        ):
            continue

        types = item.get(
            "types",
            [],
        )

        if (
            isinstance(
                types,
                list,
            )
            and "ror_display"
            in types
        ):
            return str(
                item.get(
                    "value",
                    "",
                )
            ).strip()

    for item in names:
        if isinstance(
            item,
            dict,
        ):
            value = str(
                item.get(
                    "value",
                    "",
                )
            ).strip()

            if value:
                return value

    return ""


def aliases(
    record: dict[str, Any],
    canonical_name: str,
) -> list[str]:
    names = record.get(
        "names",
        [],
    )

    values = []

    if isinstance(
        names,
        list,
    ):
        for item in names:
            if not isinstance(
                item,
                dict,
            ):
                continue

            value = str(
                item.get(
                    "value",
                    "",
                )
            ).strip()

            if (
                value
                and value != canonical_name
            ):
                values.append(
                    value
                )

    return list(
        dict.fromkeys(
            values
        )
    )


def domains(
    record: dict[str, Any],
) -> list[str]:
    raw_domains = record.get(
        "domains",
        [],
    )

    values = []

    if isinstance(
        raw_domains,
        list,
    ):
        for value in raw_domains:
            hostname = normalize_hostname(
                value
            )

            if hostname:
                values.append(
                    hostname
                )

    # If the domains field is empty, use the website link only as
    # a fallback identity hint.
    if not values:
        links = record.get(
            "links",
            [],
        )

        if isinstance(
            links,
            list,
        ):
            for link in links:
                if not isinstance(
                    link,
                    dict,
                ):
                    continue

                if link.get(
                    "type"
                ) != "website":
                    continue

                hostname = normalize_hostname(
                    str(
                        link.get(
                            "value",
                            "",
                        )
                    )
                )

                if hostname:
                    values.append(
                        hostname
                    )

    return list(
        dict.fromkeys(
            values
        )
    )


def location(
    record: dict[str, Any],
) -> tuple[
    str | None,
    str | None,
    str | None,
]:
    locations = record.get(
        "locations",
        [],
    )

    if not isinstance(
        locations,
        list,
    ):
        return (
            None,
            None,
            None,
        )

    for item in locations:
        if not isinstance(
            item,
            dict,
        ):
            continue

        details = item.get(
            "geonames_details",
            {},
        )

        if not isinstance(
            details,
            dict,
        ):
            continue

        return (
            details.get(
                "country_code"
            ),
            details.get(
                "country_name"
            ),
            details.get(
                "continent_name"
            ),
        )

    return (
        None,
        None,
        None,
    )


def organization_type(
    record: dict[str, Any],
) -> str:
    types = record.get(
        "types",
        [],
    )

    if not isinstance(
        types,
        list,
    ) or not types:
        return "other"

    first = str(
        types[0]
    ).lower()

    return TYPE_MAP.get(
        first,
        "other",
    )


def external_ids(
    record: dict[str, Any],
) -> dict[str, str]:
    values = {}

    ror_id = str(
        record.get(
            "id",
            "",
        )
    ).strip()

    if ror_id:
        values[
            "ror"
        ] = ror_id

    raw = record.get(
        "external_ids",
        [],
    )

    if isinstance(
        raw,
        list,
    ):
        for item in raw:
            if not isinstance(
                item,
                dict,
            ):
                continue

            identifier_type = str(
                item.get(
                    "type",
                    "",
                )
            ).strip().lower()

            preferred = item.get(
                "preferred"
            )

            if (
                identifier_type
                and preferred
            ):
                values[
                    identifier_type
                ] = str(
                    preferred
                )

    return values


def parse_ror_record(
    record: dict[str, Any],
) -> EntityRecord | None:
    if str(
        record.get(
            "status",
            "active",
        )
    ).lower() != "active":
        return None

    canonical = display_name(
        record
    )

    if not canonical:
        return None

    relationships = website_relationships(
        record
    )

    official_domains = list(
        dict.fromkeys(
            canonical_identity_domain(
                relationship.hostname
            )
            for relationship in relationships
            if (
                relationship.hostname
                and relationship.eligible_for_domain_identity
                and canonical_identity_domain(
                    relationship.hostname
                )
            )
        )
    )

    country_code, country_name, continent = (
        location(
            record
        )
    )

    ror_id = str(
        record.get(
            "id",
            "",
        )
    ).strip()

    evidence = {}

    for relationship in relationships:
        if not (
            relationship.hostname
            and relationship.eligible_for_domain_identity
        ):
            continue

        domain = canonical_identity_domain(
            relationship.hostname
        )

        if not domain:
            continue

        evidence.setdefault(
            domain,
            [],
        ).append(
            SourceEvidence(
                source_name="ror",
                source_record_id=ror_id,
                source_url=ror_id,
                evidence_type=(
                    "organization_registered_domain"
                ),
                confidence=0.97,
                authoritative=True,
                raw_reference=(
                    relationship.original_value
                ),
            )
        )

    return EntityRecord(
        canonical_name=canonical,
        entity_type=organization_type(
            record
        ),
        country_code=country_code,
        country_name=country_name,
        continent=continent,
        status="active",
        aliases=aliases(
            record,
            canonical,
        ),
        domains=official_domains,
        website_relationships=relationships,
        external_ids=external_ids(
            record
        ),
        evidence=evidence,
    )


def website_relationships(
    record: dict[str, Any],
) -> list:
    """
    Build semantic website relationships from ROR data.

    ROR's explicit domains field is treated as a direct
    organization-domain signal.

    Website links are classified before they can become
    domain identity evidence.
    """

    ror_id = str(
        record.get(
            "id",
            "",
        )
    ).strip()

    relationships = []

    seen = set()

    raw_domains = record.get(
        "domains",
        [],
    )

    if isinstance(
        raw_domains,
        list,
    ):
        for raw_domain in raw_domains:
            value = str(
                raw_domain or ""
            ).strip()

            if not value:
                continue

            relationship = build_website_relationship(
                value,
                source_name="ror",
                source_record_id=ror_id,
                confidence=0.97,
            )

            if not relationship.hostname:
                continue

            key = (
                relationship.original_value,
                relationship.hostname,
                relationship.relationship_type,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            relationships.append(
                relationship
            )

    links = record.get(
        "links",
        [],
    )

    if isinstance(
        links,
        list,
    ):
        for link in links:
            if not isinstance(
                link,
                dict,
            ):
                continue

            if str(
                link.get(
                    "type",
                    "",
                )
            ).lower() != "website":
                continue

            value = str(
                link.get(
                    "value",
                    "",
                )
            ).strip()

            if not value:
                continue

            relationship = build_website_relationship(
                value,
                source_name="ror",
                source_record_id=ror_id,
                confidence=0.97,
            )

            if not relationship.hostname:
                continue

            key = (
                relationship.original_value,
                relationship.hostname,
                relationship.relationship_type,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            relationships.append(
                relationship
            )

    return relationships
