from __future__ import annotations

from urllib.parse import urlsplit


def normalize_input(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if not cleaned.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):
        cleaned = (
            "https://"
            + cleaned
        )

    return cleaned


def hostname(
    value: str,
) -> str:
    cleaned = normalize_input(
        value
    )

    if not cleaned:
        return ""

    try:
        return (
            urlsplit(
                cleaned
            ).hostname
            or ""
        ).lower().rstrip(".")

    except ValueError:
        return ""
