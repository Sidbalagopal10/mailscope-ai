from __future__ import annotations

import os
from typing import Any

import requests


DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"


def api_base_url() -> str:
    return os.getenv(
        "PHISHING_DETECTOR_API_URL",
        DEFAULT_API_BASE_URL,
    ).rstrip("/")


def get_json(
    path: str,
    *,
    timeout: int = 30,
) -> dict[str, Any]:
    response = requests.get(
        f"{api_base_url()}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    payload = response.json()

    if not isinstance(
        payload,
        dict,
    ):
        raise ValueError(
            "The API returned an unsupported response."
        )

    return payload


def post_json(
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: int = 120,
) -> dict[str, Any]:
    response = requests.post(
        f"{api_base_url()}{path}",
        json=payload,
        timeout=timeout,
    )

    response.raise_for_status()

    result = response.json()

    if not isinstance(
        result,
        dict,
    ):
        raise ValueError(
            "The API returned an unsupported response."
        )

    return result


def health_status() -> dict[str, Any]:
    try:
        openapi = get_json(
            "/openapi.json",
            timeout=5,
        )

    except requests.RequestException as error:
        return {
            "available": False,
            "status": "offline",
            "error": str(error),
            "api_base_url": api_base_url(),
            "route_count": 0,
        }

    paths = openapi.get(
        "paths",
        {},
    )

    return {
        "available": True,
        "status": "online",
        "error": None,
        "api_base_url": api_base_url(),
        "route_count": (
            len(paths)
            if isinstance(paths, dict)
            else 0
        ),
    }
