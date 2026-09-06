from __future__ import annotations

import time
from typing import Any

import requests


GLEIF_API_BASE = (
    "https://api.gleif.org/api/v1"
)

USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "GlobalEntityRegistry/1.0"
)


class GLEIFError(Exception):
    pass


def request_json(
    path: str,
    *,
    params: dict[str, Any] | None = None,
    maximum_attempts: int = 5,
) -> dict[str, Any]:
    url = (
        GLEIF_API_BASE
        + path
    )

    delay = 2.0

    for attempt in range(
        1,
        maximum_attempts + 1,
    ):
        response = requests.get(
            url,
            params=params,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": (
                    "application/vnd.api+json"
                ),
            },
            timeout=60,
        )

        if response.status_code == 429:
            retry_after = (
                response.headers.get(
                    "Retry-After"
                )
            )

            try:
                wait = float(
                    retry_after
                )
            except (
                TypeError,
                ValueError,
            ):
                wait = delay

            time.sleep(
                max(
                    1.0,
                    wait,
                )
            )

            delay = min(
                delay * 2,
                60,
            )

            continue

        response.raise_for_status()

        payload = response.json()

        if not isinstance(
            payload,
            dict,
        ):
            raise GLEIFError(
                "GLEIF returned an unsupported response."
            )

        return payload

    raise GLEIFError(
        "GLEIF API remained rate-limited "
        "after repeated attempts."
    )


def search_legal_name(
    name: str,
    *,
    page_size: int = 10,
) -> dict[str, Any]:
    cleaned = str(
        name
    ).strip()

    if not cleaned:
        raise ValueError(
            "A legal entity name is required."
        )

    return request_json(
        "/lei-records",
        params={
            "filter[entity.legalName]": (
                cleaned
            ),
            "page[size]": min(
                max(
                    page_size,
                    1,
                ),
                100,
            ),
        },
    )


def fuzzy_search(
    text: str,
    *,
    page_size: int = 10,
) -> dict[str, Any]:
    cleaned = str(
        text
    ).strip()

    if not cleaned:
        raise ValueError(
            "Search text is required."
        )

    return request_json(
        "/fuzzycompletions",
        params={
            "field": "fulltext",
            "q": cleaned,
            "page[size]": min(
                max(
                    page_size,
                    1,
                ),
                100,
            ),
        },
    )


def fetch_lei(
    lei: str,
) -> dict[str, Any]:
    cleaned = str(
        lei
    ).strip().upper()

    if not cleaned:
        raise ValueError(
            "An LEI is required."
        )

    return request_json(
        f"/lei-records/{cleaned}"
    )
