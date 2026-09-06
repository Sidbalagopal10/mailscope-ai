from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

import requests


ZENODO_RECORD_ID = "21458494"

ZENODO_API_URL = (
    f"https://zenodo.org/api/records/"
    f"{ZENODO_RECORD_ID}"
)

DOWNLOAD_DIRECTORY = Path(
    "data/global_entity_registry/downloads"
)


class RORDownloadError(Exception):
    pass


def fetch_record_metadata() -> dict[str, Any]:
    response = requests.get(
        ZENODO_API_URL,
        timeout=60,
        headers={
            "User-Agent": (
                "AI-Mail-Phishing-Detector/"
                "GlobalEntityRegistry"
            )
        },
    )

    response.raise_for_status()

    payload = response.json()

    if not isinstance(
        payload,
        dict,
    ):
        raise RORDownloadError(
            "Zenodo returned an unsupported response."
        )

    return payload


def choose_ror_zip(
    metadata: dict[str, Any],
) -> dict[str, Any]:
    files = metadata.get(
        "files",
        [],
    )

    candidates = []

    for item in files:
        if not isinstance(
            item,
            dict,
        ):
            continue

        key = str(
            item.get(
                "key",
                "",
            )
        )

        if (
            key.endswith(
                "-ror-data.zip"
            )
            and "v2." in key
        ):
            candidates.append(
                item
            )

    if not candidates:
        raise RORDownloadError(
            "Could not locate the ROR v2 data ZIP."
        )

    candidates.sort(
        key=lambda item: item.get(
            "key",
            ""
        ),
        reverse=True,
    )

    return candidates[0]


def download_latest_ror_dump(
    *,
    force: bool = False,
) -> Path:
    DOWNLOAD_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    metadata = fetch_record_metadata()

    selected = choose_ror_zip(
        metadata
    )

    filename = str(
        selected[
            "key"
        ]
    )

    destination = (
        DOWNLOAD_DIRECTORY
        / filename
    )

    if (
        destination.exists()
        and destination.stat().st_size > 0
        and not force
    ):
        return destination

    links = selected.get(
        "links",
        {},
    )

    download_url = (
        links.get(
            "self"
        )
        or links.get(
            "download"
        )
    )

    if not download_url:
        raise RORDownloadError(
            "ROR download URL was unavailable."
        )

    with requests.get(
        download_url,
        stream=True,
        timeout=180,
        headers={
            "User-Agent": (
                "AI-Mail-Phishing-Detector/"
                "GlobalEntityRegistry"
            )
        },
    ) as response:
        response.raise_for_status()

        temporary = destination.with_suffix(
            destination.suffix
            + ".part"
        )

        with temporary.open(
            "wb"
        ) as handle:
            for chunk in response.iter_content(
                chunk_size=1024 * 1024
            ):
                if chunk:
                    handle.write(
                        chunk
                    )

        temporary.replace(
            destination
        )

    return destination


def inspect_zip(
    zip_path: Path,
) -> list[str]:
    with zipfile.ZipFile(
        zip_path
    ) as archive:
        return archive.namelist()


def find_json_member(
    zip_path: Path,
) -> str:
    with zipfile.ZipFile(
        zip_path
    ) as archive:
        members = archive.namelist()

    json_candidates = [
        member
        for member in members
        if member.lower().endswith(
            ".json"
        )
    ]

    if not json_candidates:
        raise RORDownloadError(
            "No JSON file was found in the ROR archive."
        )

    preferred = [
        member
        for member in json_candidates
        if "schema_v2" in member.lower()
        or "ror-data" in member.lower()
    ]

    return (
        preferred[0]
        if preferred
        else json_candidates[0]
    )


def load_ror_records(
    zip_path: Path,
) -> list[dict[str, Any]]:
    member = find_json_member(
        zip_path
    )

    with zipfile.ZipFile(
        zip_path
    ) as archive:
        raw = archive.read(
            member
        )

    payload = json.loads(
        raw.decode(
            "utf-8"
        )
    )

    if isinstance(
        payload,
        list,
    ):
        records = payload

    elif isinstance(
        payload,
        dict,
    ):
        records = (
            payload.get(
                "items"
            )
            or payload.get(
                "records"
            )
            or []
        )

    else:
        records = []

    if not isinstance(
        records,
        list,
    ):
        raise RORDownloadError(
            "ROR JSON did not contain a record list."
        )

    return [
        item
        for item in records
        if isinstance(
            item,
            dict,
        )
    ]


if __name__ == "__main__":
    path = download_latest_ror_dump()

    print(
        "Downloaded:",
        path,
    )

    print(
        "Archive members:"
    )

    for member in inspect_zip(
        path
    ):
        print(
            "-",
            member,
        )
