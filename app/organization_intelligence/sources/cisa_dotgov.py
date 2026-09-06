from __future__ import annotations

import csv
import hashlib
import json
import shutil
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.organization_intelligence.store import (
    OrganizationIntelligenceError,
    normalize_domain,
    upsert_organization_domain,
)


SOURCE_NAME = "CISA .gov Registry"

SOURCE_TYPE = "government_domain_registry"

SOURCE_PAGE_URL = "https://get.gov/about/data/"

DATASET_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/dotgov-data/main/current-full.csv"
)

DOWNLOAD_DIRECTORY = Path(
    "data/organization_intelligence/downloads"
)

CURRENT_FILE = (
    DOWNLOAD_DIRECTORY
    / "cisa_current_full.csv"
)

METADATA_FILE = (
    DOWNLOAD_DIRECTORY
    / "cisa_current_full.metadata.json"
)

REQUIRED_COLUMNS = {
    "Domain name",
    "Domain type",
    "Organization name",
    "Suborganization name",
    "City",
    "State",
}


class CisaDotGovImportError(
    OrganizationIntelligenceError
):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as file_handle:
        for chunk in iter(
            lambda: file_handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(
                chunk
            )

    return digest.hexdigest()


def download_dataset(
    *,
    force: bool = False,
    timeout: int = 60,
) -> dict[str, Any]:
    DOWNLOAD_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        CURRENT_FILE.exists()
        and not force
    ):
        return {
            "status": "cached",
            "path": str(
                CURRENT_FILE
            ),
            "sha256": sha256_file(
                CURRENT_FILE
            ),
            "downloaded_at": (
                json.loads(
                    METADATA_FILE.read_text(
                        encoding="utf-8"
                    )
                ).get(
                    "downloaded_at"
                )
                if METADATA_FILE.exists()
                else None
            ),
        }

    temporary_file = (
        DOWNLOAD_DIRECTORY
        / "cisa_current_full.csv.part"
    )

    request = urllib.request.Request(
        DATASET_URL,
        headers={
            "User-Agent": (
                "AI-Email-Security-Platform/1.0"
            )
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            content_type = response.headers.get(
                "Content-Type",
                "",
            )

            with temporary_file.open(
                "wb"
            ) as output_file:
                shutil.copyfileobj(
                    response,
                    output_file,
                )

    except Exception as error:
        temporary_file.unlink(
            missing_ok=True
        )

        raise CisaDotGovImportError(
            "Unable to download the CISA "
            f".gov dataset: {error}"
        ) from error

    if (
        not temporary_file.exists()
        or temporary_file.stat().st_size
        < 1000
    ):
        temporary_file.unlink(
            missing_ok=True
        )

        raise CisaDotGovImportError(
            "The downloaded dataset is empty "
            "or unexpectedly small."
        )

    validate_dataset(
        temporary_file
    )

    temporary_file.replace(
        CURRENT_FILE
    )

    metadata = {
        "source_name": SOURCE_NAME,
        "source_page_url": SOURCE_PAGE_URL,
        "dataset_url": DATASET_URL,
        "downloaded_at": utc_now(),
        "sha256": sha256_file(
            CURRENT_FILE
        ),
        "size_bytes": (
            CURRENT_FILE.stat().st_size
        ),
        "content_type": content_type,
    }

    METADATA_FILE.write_text(
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return {
        "status": "downloaded",
        "path": str(
            CURRENT_FILE
        ),
        **metadata,
    }


def validate_dataset(
    path: Path,
) -> dict[str, Any]:
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file_handle:
            reader = csv.DictReader(
                file_handle
            )

            columns = set(
                reader.fieldnames
                or []
            )

            missing = (
                REQUIRED_COLUMNS
                - columns
            )

            if missing:
                raise CisaDotGovImportError(
                    "CISA dataset is missing "
                    "required columns: "
                    f"{sorted(missing)}"
                )

            row_count = sum(
                1
                for _ in reader
            )

    except UnicodeDecodeError as error:
        raise CisaDotGovImportError(
            "The CISA dataset is not valid UTF-8."
        ) from error

    if row_count == 0:
        raise CisaDotGovImportError(
            "The CISA dataset contains no records."
        )

    return {
        "valid": True,
        "row_count": row_count,
        "columns": sorted(
            columns
        ),
    }


def normalize_entity_type(
    domain_type: str,
) -> str:
    normalized = str(
        domain_type or ""
    ).strip().lower()

    if "school district" in normalized:
        return "school"

    return "government"


def build_legal_name(
    row: dict[str, str],
) -> str:
    organization = str(
        row.get(
            "Organization name",
            "",
        )
        or ""
    ).strip()

    suborganization = str(
        row.get(
            "Suborganization name",
            "",
        )
        or ""
    ).strip()

    if (
        suborganization
        and suborganization.lower()
        not in organization.lower()
    ):
        return (
            f"{organization} — "
            f"{suborganization}"
        )

    return organization


def calculate_identity_confidence(
    row: dict[str, str],
) -> float:
    confidence = 94.0

    if row.get(
        "Organization name",
        ""
    ).strip():
        confidence += 2

    if row.get(
        "Domain type",
        ""
    ).strip():
        confidence += 1

    if row.get(
        "State",
        ""
    ).strip():
        confidence += 1

    return min(
        confidence,
        98.0,
    )


def import_dataset(
    *,
    path: Path | None = None,
    force_download: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    if path is None:
        download_result = download_dataset(
            force=force_download
        )

        dataset_path = Path(
            download_result["path"]
        )

    else:
        dataset_path = Path(
            path
        )

        download_result = {
            "status": "provided",
            "path": str(
                dataset_path
            ),
        }

    validation = validate_dataset(
        dataset_path
    )

    imported = 0
    failed = 0
    skipped = 0
    errors: list[dict[str, Any]] = []

    with dataset_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file_handle:
        reader = csv.DictReader(
            file_handle
        )

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
                domain = normalize_domain(
                    row.get(
                        "Domain name",
                        ""
                    )
                )

                legal_name = build_legal_name(
                    row
                )

                if not legal_name:
                    skipped += 1
                    continue

                domain_type = str(
                    row.get(
                        "Domain type",
                        ""
                    )
                    or "Government"
                ).strip()

                city = str(
                    row.get(
                        "City",
                        ""
                    )
                    or ""
                ).strip()

                state = str(
                    row.get(
                        "State",
                        ""
                    )
                    or ""
                ).strip()

                jurisdiction_parts = [
                    value
                    for value in (
                        city,
                        state,
                    )
                    if value
                ]

                jurisdiction = (
                    ", ".join(
                        jurisdiction_parts
                    )
                    or None
                )

                upsert_organization_domain(
                    legal_name=legal_name,
                    entity_type=(
                        normalize_entity_type(
                            domain_type
                        )
                    ),
                    domain=domain,
                    source_name=SOURCE_NAME,
                    source_type=SOURCE_TYPE,
                    source_record_id=domain,
                    source_url=SOURCE_PAGE_URL,
                    authoritative_source=True,
                    country_code="US",
                    jurisdiction=jurisdiction,
                    registration_status="registered",
                    identity_state=(
                        "VERIFIED_ESTABLISHED"
                    ),
                    security_state="NEUTRAL",
                    identity_confidence=(
                        calculate_identity_confidence(
                            row
                        )
                    ),
                    security_confidence=35,
                    domain_relationship=(
                        "authoritative_registry"
                    ),
                    evidence_type=(
                        "official_government_domain"
                    ),
                    evidence_value=(
                        json.dumps(
                            {
                                "domain_type": (
                                    domain_type
                                ),
                                "organization": (
                                    row.get(
                                        "Organization name"
                                    )
                                ),
                                "suborganization": (
                                    row.get(
                                        "Suborganization name"
                                    )
                                ),
                                "city": city,
                                "state": state,
                            },
                            sort_keys=True,
                        )
                    ),
                )

                imported += 1

            except Exception as error:
                failed += 1

                if len(errors) < 100:
                    errors.append(
                        {
                            "row": row_number,
                            "domain": row.get(
                                "Domain name"
                            ),
                            "error": str(
                                error
                            ),
                        }
                    )

    return {
        "source": SOURCE_NAME,
        "dataset": str(
            dataset_path
        ),
        "download": download_result,
        "validation": validation,
        "imported": imported,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "completed_at": utc_now(),
    }


def main() -> None:
    result = import_dataset()

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
