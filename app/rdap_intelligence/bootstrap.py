from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests


IANA_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)

CACHE_FILE = Path(
    "data/rdap_intelligence/"
    "iana_dns_bootstrap.json"
)

USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "RDAP-Research/1.0"
)


def load_bootstrap(
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    CACHE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        CACHE_FILE.exists()
        and CACHE_FILE.stat().st_size > 0
        and not force_refresh
    ):
        return json.loads(
            CACHE_FILE.read_text(
                encoding="utf-8"
            )
        )

    response = requests.get(
        IANA_BOOTSTRAP_URL,
        timeout=60,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )

    response.raise_for_status()

    payload = response.json()

    CACHE_FILE.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return payload


def server_for_tld(
    tld: str,
    *,
    force_refresh: bool = False,
) -> str | None:
    cleaned = str(
        tld or ""
    ).strip().lower().lstrip(".")

    if not cleaned:
        return None

    payload = load_bootstrap(
        force_refresh=force_refresh
    )

    services = payload.get(
        "services",
        [],
    )

    for item in services:
        if (
            not isinstance(
                item,
                list,
            )
            or len(item) < 2
        ):
            continue

        tlds = item[0]
        servers = item[1]

        if (
            isinstance(
                tlds,
                list,
            )
            and cleaned
            in {
                str(value).lower()
                for value in tlds
            }
            and isinstance(
                servers,
                list,
            )
            and servers
        ):
            return str(
                servers[0]
            ).rstrip("/")

    return None
