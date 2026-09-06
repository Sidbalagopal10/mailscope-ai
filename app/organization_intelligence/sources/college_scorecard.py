from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.organization_intelligence.store import (
    normalize_domain,
    upsert_organization_domain,
)


SOURCE_NAME = (
    "U.S. Department of Education College Scorecard"
)

SOURCE_TYPE = (
    "postsecondary_education_registry"
)

SOURCE_PAGE_URL = (
    "https://collegescorecard.ed.gov/data/"
)


COLUMN_ALIASES = {
    "unit_id": (
        "UNITID",
        "id",
        "school.id",
    ),
    "institution_name": (
        "INSTNM",
        "school.name",
        "institution_name",
    ),
    "website": (
        "INSTURL",
        "school.school_url",
        "school_url",
    ),
    "state": (
        "STABBR",
        "school.state",
        "state",
    ),
    "city": (
        "CITY",
        "school.city",
        "city",
    ),
    "status": (
        "CURROPER",
        "school.operating",
        "operating",
    ),
    "ownership": (
        "CONTROL",
        "school.ownership",
        "ownership",
    ),
}


def detect_columns(
    fieldnames: list[str],
) -> dict[str, str]:
    available = {
        name.strip(): name
        for name in fieldnames
        if name
    }

    resolved: dict[str, str] = {}

    for logical_name, aliases in (
        COLUMN_ALIASES.items()
    ):
        for alias in aliases:
            if alias in available:
                resolved[logical_name] = (
                    available[alias]
                )
                break

    required = {
        "unit_id",
        "institution_name",
        "website",
    }

    missing = required - set(resolved)

    if missing:
        raise ValueError(
            "College Scorecard CSV is missing "
            f"required columns: {sorted(missing)}"
        )

    return resolved


def validate_csv(
    csv_path: Path,
) -> dict[str, Any]:
    if not csv_path.exists():
        raise FileNotFoundError(
            f"CSV not found: {csv_path}"
        )

    with csv_path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as file_handle:
        reader = csv.DictReader(file_handle)

        fieldnames = list(
            reader.fieldnames or []
        )

        columns = detect_columns(
            fieldnames
        )

        row_count = sum(
            1 for _ in reader
        )

    return {
        "valid": True,
        "row_count": row_count,
        "columns": columns,
    }


def first_value(
    row: dict[str, str],
    column_name: str | None,
) -> str:
    if not column_name:
        return ""

    return str(
        row.get(
            column_name,
            "",
        )
        or ""
    ).strip()


def normalize_website(
    website: str,
) -> str:
    value = str(
        website or ""
    ).strip()

    if not value:
        raise ValueError(
            "Institution website is missing."
        )

    # Some rows may contain more than one value.
    value = value.split(",")[0].strip()
    value = value.split()[0].strip()

    if not value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        value = "https://" + value

    hostname = (
        urlparse(value).hostname
        or value
    )

    return normalize_domain(
        hostname
    )


def operating_status(
    raw_value: str,
) -> str:
    normalized = str(
        raw_value or ""
    ).strip().lower()

    if normalized in {
        "1",
        "true",
        "yes",
        "operating",
    }:
        return "active"

    if normalized in {
        "0",
        "false",
        "no",
        "closed",
    }:
        return "inactive"

    return "reported"


def calculate_identity_confidence(
    *,
    domain: str,
    unit_id: str,
    state: str,
    city: str,
    active_status: str,
) -> float:
    confidence = 82.0

    if domain.endswith(".edu"):
        confidence += 8

    if unit_id:
        confidence += 3

    if state:
        confidence += 2

    if city:
        confidence += 1

    if active_status == "active":
        confidence += 2

    return min(
        confidence,
        96.0,
    )


def import_csv(
    csv_path: Path,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    validation = validate_csv(
        csv_path
    )

    columns = validation["columns"]

    imported = 0
    failed = 0
    skipped = 0
    duplicate_domains = 0
    errors: list[dict[str, Any]] = []
    seen_domains: set[str] = set()

    with csv_path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as file_handle:
        reader = csv.DictReader(file_handle)

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            if (
                limit is not None
                and imported >= limit
            ):
                break

            try:
                institution_name = first_value(
                    row,
                    columns.get(
                        "institution_name"
                    ),
                )

                website = first_value(
                    row,
                    columns.get(
                        "website"
                    ),
                )

                unit_id = first_value(
                    row,
                    columns.get(
                        "unit_id"
                    ),
                )

                if (
                    not institution_name
                    or not website
                ):
                    skipped += 1
                    continue

                domain = normalize_website(
                    website
                )

                if domain in seen_domains:
                    duplicate_domains += 1
                    continue

                seen_domains.add(domain)

                state = first_value(
                    row,
                    columns.get("state"),
                )

                city = first_value(
                    row,
                    columns.get("city"),
                )

                status_raw = first_value(
                    row,
                    columns.get("status"),
                )

                ownership = first_value(
                    row,
                    columns.get("ownership"),
                )

                active_status = (
                    operating_status(
                        status_raw
                    )
                )

                jurisdiction = ", ".join(
                    value
                    for value in (
                        city,
                        state,
                    )
                    if value
                ) or None

                confidence = (
                    calculate_identity_confidence(
                        domain=domain,
                        unit_id=unit_id,
                        state=state,
                        city=city,
                        active_status=active_status,
                    )
                )

                upsert_organization_domain(
                    legal_name=(
                        institution_name
                    ),
                    entity_type="university",
                    domain=domain,
                    source_name=SOURCE_NAME,
                    source_type=SOURCE_TYPE,
                    source_record_id=unit_id,
                    source_url=SOURCE_PAGE_URL,
                    authoritative_source=True,
                    country_code="US",
                    jurisdiction=jurisdiction,
                    registration_status=(
                        active_status
                    ),
                    identity_state=(
                        "VERIFIED_ESTABLISHED"
                        if confidence >= 90
                        else "PROVISIONAL"
                    ),
                    security_state="NEUTRAL",
                    identity_confidence=(
                        confidence
                    ),
                    security_confidence=35,
                    domain_relationship=(
                        "institution_reported"
                    ),
                    evidence_type=(
                        "federal_education_"
                        "institution_domain"
                    ),
                    evidence_value=json.dumps(
                        {
                            "unit_id": unit_id,
                            "institution_name": (
                                institution_name
                            ),
                            "reported_website": (
                                website
                            ),
                            "ownership": ownership,
                            "city": city,
                            "state": state,
                            "operating_status": (
                                active_status
                            ),
                        },
                        sort_keys=True,
                    ),
                )

                imported += 1

            except Exception as error:
                failed += 1

                if len(errors) < 50:
                    errors.append(
                        {
                            "row": row_number,
                            "institution": (
                                row.get(
                                    columns.get(
                                        "institution_name",
                                        "",
                                    )
                                )
                            ),
                            "website": (
                                row.get(
                                    columns.get(
                                        "website",
                                        "",
                                    )
                                )
                            ),
                            "error": str(error),
                        }
                    )

    return {
        "source": SOURCE_NAME,
        "csv_path": str(csv_path),
        "validation": validation,
        "imported": imported,
        "failed": failed,
        "skipped": skipped,
        "duplicate_domains": (
            duplicate_domains
        ),
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import College Scorecard "
            "institution domains."
        )
    )

    parser.add_argument(
        "--csv",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    arguments = parser.parse_args()

    result = import_csv(
        arguments.csv.expanduser(),
        limit=arguments.limit,
    )

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
