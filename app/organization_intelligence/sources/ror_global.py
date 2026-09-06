from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.organization_intelligence.store import (
    OrganizationIntelligenceError,
    normalize_domain,
    upsert_organization_domain,
)


SOURCE_NAME = "Research Organization Registry"

SOURCE_TYPE = "global_research_organization_registry"

SOURCE_PAGE_URL = "https://ror.org/"

ZENODO_CONCEPT_RECORD_ID = "6347574"

ZENODO_API_URL = (
    "https://zenodo.org/api/records/"
    f"{ZENODO_CONCEPT_RECORD_ID}"
)

DOWNLOAD_DIRECTORY = Path(
    "data/organization_intelligence/downloads"
)

ARCHIVE_PATH = (
    DOWNLOAD_DIRECTORY
    / "ror_latest_data.zip"
)

METADATA_PATH = (
    DOWNLOAD_DIRECTORY
    / "ror_latest_data.metadata.json"
)


class RorImportError(
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

    with path.open("rb") as file_handle:
        for chunk in iter(
            lambda: file_handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def request_json(
    url: str,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "AI-Email-Security-Platform/1.0"
            ),
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            return json.load(response)

    except Exception as error:
        raise RorImportError(
            f"Unable to retrieve ROR metadata: {error}"
        ) from error


def select_archive_file(
    metadata: dict[str, Any],
) -> dict[str, Any]:
    files = metadata.get(
        "files",
        [],
    )

    zip_candidates = [
        item
        for item in files
        if str(
            item.get(
                "key",
                "",
            )
        ).lower().endswith(".zip")
    ]

    if not zip_candidates:
        raise RorImportError(
            "The latest ROR release does not "
            "contain a ZIP archive."
        )

    preferred = [
        item
        for item in zip_candidates
        if "ror-data" in str(
            item.get(
                "key",
                "",
            )
        ).lower()
    ]

    candidates = preferred or zip_candidates

    candidates.sort(
        key=lambda item: int(
            item.get(
                "size",
                0,
            )
            or 0
        ),
        reverse=True,
    )

    return candidates[0]


def download_dataset(
    *,
    force: bool = False,
    timeout: int = 180,
) -> dict[str, Any]:
    DOWNLOAD_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        ARCHIVE_PATH.exists()
        and METADATA_PATH.exists()
        and not force
    ):
        cached_metadata = json.loads(
            METADATA_PATH.read_text(
                encoding="utf-8"
            )
        )

        return {
            "status": "cached",
            "path": str(ARCHIVE_PATH),
            **cached_metadata,
        }

    release_metadata = request_json(
        ZENODO_API_URL,
        timeout=timeout,
    )

    selected_file = select_archive_file(
        release_metadata
    )

    links = selected_file.get(
        "links",
        {},
    )

    download_url = (
        links.get("self")
        or links.get("download")
    )

    if not download_url:
        raise RorImportError(
            "ROR archive download URL is missing."
        )

    temporary_path = ARCHIVE_PATH.with_suffix(
        ".zip.part"
    )

    request = urllib.request.Request(
        download_url,
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
            with temporary_path.open(
                "wb"
            ) as output_file:
                shutil.copyfileobj(
                    response,
                    output_file,
                )

    except Exception as error:
        temporary_path.unlink(
            missing_ok=True
        )

        raise RorImportError(
            f"Unable to download ROR data: {error}"
        ) from error

    if temporary_path.stat().st_size < 1000:
        temporary_path.unlink(
            missing_ok=True
        )

        raise RorImportError(
            "Downloaded ROR archive is "
            "unexpectedly small."
        )

    try:
        with zipfile.ZipFile(
            temporary_path,
            "r",
        ) as archive:
            if archive.testzip() is not None:
                raise RorImportError(
                    "ROR archive failed ZIP validation."
                )

    except zipfile.BadZipFile as error:
        temporary_path.unlink(
            missing_ok=True
        )

        raise RorImportError(
            "Downloaded ROR file is not "
            "a valid ZIP archive."
        ) from error

    temporary_path.replace(
        ARCHIVE_PATH
    )

    local_metadata = {
        "release_id": release_metadata.get("id"),
        "release_doi": release_metadata.get("doi"),
        "release_title": release_metadata.get(
            "metadata",
            {},
        ).get("title"),
        "archive_filename": selected_file.get("key"),
        "downloaded_at": utc_now(),
        "sha256": sha256_file(ARCHIVE_PATH),
        "size_bytes": ARCHIVE_PATH.stat().st_size,
    }

    METADATA_PATH.write_text(
        json.dumps(
            local_metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return {
        "status": "downloaded",
        "path": str(ARCHIVE_PATH),
        **local_metadata,
    }


def locate_json_file(
    archive_path: Path,
) -> str:
    with zipfile.ZipFile(
        archive_path,
        "r",
    ) as archive:
        names = [
            name
            for name in archive.namelist()
            if (
                name.lower().endswith(".json")
                and "__macosx" not in name.lower()
            )
        ]

    if not names:
        raise RorImportError(
            "ROR archive contains no JSON data file."
        )

    preferred = [
        name
        for name in names
        if (
            "ror-data" in name.lower()
            and "schema_v1" not in name.lower()
        )
    ]

    candidates = preferred or names

    candidates.sort(
        key=lambda name: (
            "schema_v2" not in name.lower(),
            name.count("/"),
            len(name),
        )
    )

    return candidates[0]


def load_records(
    archive_path: Path,
) -> list[dict[str, Any]]:
    json_name = locate_json_file(
        archive_path
    )

    with zipfile.ZipFile(
        archive_path,
        "r",
    ) as archive:
        with archive.open(
            json_name
        ) as file_handle:
            payload = json.load(
                file_handle
            )

    if isinstance(payload, list):
        records = payload

    elif isinstance(payload, dict):
        records = (
            payload.get("items")
            or payload.get("records")
            or payload.get("organizations")
            or []
        )

    else:
        records = []

    if not isinstance(records, list):
        raise RorImportError(
            "ROR JSON has an unsupported structure."
        )

    return records


def preferred_name(
    record: dict[str, Any],
) -> str:
    names = record.get(
        "names",
        [],
    )

    for name in names:
        types = {
            str(value).lower()
            for value in name.get(
                "types",
                []
            )
        }

        if "ror_display" in types:
            value = str(
                name.get(
                    "value",
                    "",
                )
            ).strip()

            if value:
                return value

    for name in names:
        value = str(
            name.get(
                "value",
                "",
            )
        ).strip()

        if value:
            return value

    legacy_name = str(
        record.get(
            "name",
            "",
        )
    ).strip()

    return legacy_name


def organization_country(
    record: dict[str, Any],
) -> tuple[
    str | None,
    str | None,
]:
    locations = record.get(
        "locations",
        [],
    )

    for location in locations:
        details = location.get(
            "geonames_details",
            {},
        )

        country_code = details.get(
            "country_code"
        )

        country_name = details.get(
            "country_name"
        )

        if country_code or country_name:
            return (
                str(country_code)
                if country_code
                else None,
                str(country_name)
                if country_name
                else None,
            )

    legacy_country = record.get(
        "country",
        {},
    )

    if isinstance(
        legacy_country,
        dict,
    ):
        return (
            legacy_country.get(
                "country_code"
            ),
            legacy_country.get(
                "country_name"
            ),
        )

    return (None, None)


def map_entity_type(
    record: dict[str, Any],
) -> str:
    record_types = {
        str(value).lower()
        for value in record.get(
            "types",
            []
        )
    }

    if {
        "education",
        "facility",
    } & record_types:
        return "university"

    if "healthcare" in record_types:
        return "hospital"

    if "company" in record_types:
        return "corporation"

    if "government" in record_types:
        return "government"

    if {
        "nonprofit",
        "funder",
        "archive",
    } & record_types:
        return "nonprofit"

    return "unknown"


def extract_domains(
    record: dict[str, Any],
) -> set[str]:
    domains: set[str] = set()

    for domain in record.get(
        "domains",
        [],
    ):
        try:
            domains.add(
                normalize_domain(
                    str(domain)
                )
            )
        except Exception:
            continue

    for link in record.get(
        "links",
        [],
    ):
        if isinstance(link, dict):
            link_type = str(
                link.get(
                    "type",
                    "",
                )
            ).lower()

            value = str(
                link.get(
                    "value",
                    "",
                )
            ).strip()

            if (
                link_type
                and link_type
                not in {
                    "website",
                    "homepage",
                }
            ):
                continue

        else:
            value = str(link).strip()

        if not value:
            continue

        try:
            parsed = urlparse(
                value
                if "://" in value
                else f"https://{value}"
            )

            hostname = parsed.hostname

            if hostname:
                domains.add(
                    normalize_domain(
                        hostname
                    )
                )

        except Exception:
            continue

    return domains


def identity_confidence(
    *,
    domain: str,
    record: dict[str, Any],
    country_code: str | None,
) -> float:
    confidence = 76.0

    if record.get("id"):
        confidence += 5

    if domain in set(
        record.get(
            "domains",
            [],
        )
    ):
        confidence += 8

    if country_code:
        confidence += 3

    if domain.endswith(
        (
            ".edu",
            ".ac.uk",
            ".edu.au",
            ".ac.in",
        )
    ):
        confidence += 4

    return min(
        confidence,
        94.0,
    )


def import_dataset(
    *,
    archive_path: Path | None = None,
    force_download: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    if archive_path is None:
        download = download_dataset(
            force=force_download
        )

        selected_archive = Path(
            download["path"]
        )

    else:
        selected_archive = Path(
            archive_path
        ).expanduser()

        download = {
            "status": "provided",
            "path": str(
                selected_archive
            ),
        }

    records = load_records(
        selected_archive
    )

    imported_domains = 0
    imported_organizations = 0
    skipped_without_domain = 0
    skipped_inactive = 0
    failed = 0
    errors: list[dict[str, Any]] = []

    for record_number, record in enumerate(
        records,
        start=1,
    ):
        if (
            limit is not None
            and imported_organizations
            >= limit
        ):
            break

        try:
            status = str(
                record.get(
                    "status",
                    "active",
                )
            ).lower()

            if status not in {
                "active",
                "",
            }:
                skipped_inactive += 1
                continue

            legal_name = preferred_name(
                record
            )

            if not legal_name:
                failed += 1
                continue

            domains = extract_domains(
                record
            )

            if not domains:
                skipped_without_domain += 1
                continue

            country_code, country_name = (
                organization_country(
                    record
                )
            )

            entity_type = map_entity_type(
                record
            )

            organization_imported = False

            for domain in sorted(domains):
                confidence = identity_confidence(
                    domain=domain,
                    record=record,
                    country_code=country_code,
                )

                upsert_organization_domain(
                    legal_name=legal_name,
                    entity_type=entity_type,
                    domain=domain,
                    source_name=SOURCE_NAME,
                    source_type=SOURCE_TYPE,
                    source_record_id=str(
                        record.get(
                            "id",
                            "",
                        )
                    ),
                    source_url=SOURCE_PAGE_URL,
                    authoritative_source=True,
                    country_code=country_code,
                    jurisdiction=country_name,
                    registration_status=status,
                    identity_state=(
                        "VERIFIED_ESTABLISHED"
                        if confidence >= 88
                        else "PROVISIONAL"
                    ),
                    security_state="NEUTRAL",
                    identity_confidence=confidence,
                    security_confidence=30,
                    domain_relationship=(
                        "ror_reported_web_presence"
                    ),
                    evidence_type=(
                        "global_research_organization_domain"
                    ),
                    evidence_value=json.dumps(
                        {
                            "ror_id": record.get("id"),
                            "name": legal_name,
                            "types": record.get(
                                "types",
                                [],
                            ),
                            "country_code": (
                                country_code
                            ),
                            "country_name": (
                                country_name
                            ),
                            "status": status,
                        },
                        sort_keys=True,
                    ),
                )

                imported_domains += 1
                organization_imported = True

            if organization_imported:
                imported_organizations += 1

        except Exception as error:
            failed += 1

            if len(errors) < 100:
                errors.append(
                    {
                        "record": record_number,
                        "ror_id": record.get("id"),
                        "name": preferred_name(
                            record
                        ),
                        "error": str(error),
                    }
                )

    return {
        "source": SOURCE_NAME,
        "archive": str(
            selected_archive
        ),
        "download": download,
        "total_records_in_dump": len(records),
        "imported_organizations": (
            imported_organizations
        ),
        "imported_domains": (
            imported_domains
        ),
        "skipped_without_domain": (
            skipped_without_domain
        ),
        "skipped_inactive": (
            skipped_inactive
        ),
        "failed": failed,
        "errors": errors,
        "completed_at": utc_now(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import worldwide organizations "
            "from the ROR data dump."
        )
    )

    parser.add_argument(
        "--archive",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--force-download",
        action="store_true",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    arguments = parser.parse_args()

    result = import_dataset(
        archive_path=arguments.archive,
        force_download=(
            arguments.force_download
        ),
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
