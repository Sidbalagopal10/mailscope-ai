from __future__ import annotations

import re
import unicodedata


CORPORATE_SUFFIXES = {
    "inc",
    "incorporated",
    "corp",
    "corporation",
    "company",
    "co",
    "limited",
    "ltd",
    "llc",
    "plc",
    "gmbh",
    "ag",
    "sa",
    "sas",
    "bv",
    "nv",
    "pte",
    "pty",
}


def normalize_organization_name(
    value: str | None,
) -> str:
    text = str(
        value or ""
    ).strip()

    if not text:
        return ""

    text = unicodedata.normalize(
        "NFKD",
        text,
    )

    text = "".join(
        character
        for character in text
        if not unicodedata.combining(
            character
        )
    )

    text = text.lower()

    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        text,
    )

    tokens = [
        token
        for token in text.split()
        if token
    ]

    return " ".join(
        tokens
    )


def organization_core_tokens(
    value: str | None,
) -> list[str]:
    normalized = normalize_organization_name(
        value
    )

    tokens = normalized.split()

    while (
        tokens
        and tokens[-1]
        in CORPORATE_SUFFIXES
    ):
        tokens.pop()

    return tokens


def organization_core_name(
    value: str | None,
) -> str:
    return " ".join(
        organization_core_tokens(
            value
        )
    )
