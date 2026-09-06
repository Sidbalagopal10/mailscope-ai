from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import requests

from app.global_entity_registry.public_suffix import (
    registrable_domain,
)
from app.rdap_intelligence.bootstrap import (
    server_for_tld,
)
from app.rdap_intelligence.cache import (
    get_cached,
    save_cached,
    utc_now,
)


USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "RDAP-Research/1.0"
)


def parse_datetime(
    value: str | None,
) -> datetime | None:
    if not value:
        return None

    cleaned = str(
        value
    ).strip()

    if cleaned.endswith(
        "Z"
    ):
        cleaned = (
            cleaned[:-1]
            + "+00:00"
        )

    try:
        result = datetime.fromisoformat(
            cleaned
        )

        if result.tzinfo is None:
            result = result.replace(
                tzinfo=timezone.utc
            )

        return result.astimezone(
            timezone.utc
        )

    except ValueError:
        return None


def event_date(
    payload: dict[str, Any],
    actions: set[str],
) -> str | None:
    events = payload.get(
        "events",
        [],
    )

    if not isinstance(
        events,
        list,
    ):
        return None

    for event in events:
        if not isinstance(
            event,
            dict,
        ):
            continue

        action = str(
            event.get(
                "eventAction",
                "",
            )
        ).lower()

        if action in actions:
            value = event.get(
                "eventDate"
            )

            if value:
                return str(
                    value
                )

    return None


def registrar_name(
    payload: dict[str, Any],
) -> str | None:
    entities = payload.get(
        "entities",
        [],
    )

    if not isinstance(
        entities,
        list,
    ):
        return None

    for entity in entities:
        if not isinstance(
            entity,
            dict,
        ):
            continue

        roles = entity.get(
            "roles",
            [],
        )

        if (
            not isinstance(
                roles,
                list,
            )
            or "registrar"
            not in {
                str(role).lower()
                for role in roles
            }
        ):
            continue

        vcard = entity.get(
            "vcardArray"
        )

        if (
            not isinstance(
                vcard,
                list,
            )
            or len(vcard) < 2
            or not isinstance(
                vcard[1],
                list,
            )
        ):
            continue

        for item in vcard[1]:
            if (
                isinstance(
                    item,
                    list,
                )
                and len(item) >= 4
                and item[0] == "fn"
            ):
                return str(
                    item[3]
                )

    return None


def analyze_domain(
    value: str,
    *,
    force_refresh: bool = False,
    maximum_attempts: int = 3,
) -> dict[str, Any]:
    domain = registrable_domain(
        value
    )

    if not domain:
        return {
            "status": "unavailable",
            "domain": "",
            "error": (
                "Unable to determine registrable domain."
            ),
        }

    if not force_refresh:
        cached = get_cached(
            domain
        )

        if cached:
            return {
                **cached,
                "cache_hit": True,
            }

    tld = domain.rsplit(
        ".",
        1,
    )[-1]

    server = server_for_tld(
        tld
    )

    if not server:
        result = {
            "domain": domain,
            "status": "unsupported_tld",
            "rdap_server": None,
            "fetched_at": utc_now(),
            "error": (
                f"No RDAP bootstrap server for .{tld}"
            ),
        }

        save_cached(
            result
        )

        return result

    url = (
        f"{server}/domain/{domain}"
    )

    delay = 1.5

    for attempt in range(
        maximum_attempts
    ):
        try:
            response = requests.get(
                url,
                timeout=20,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": (
                        "application/rdap+json,"
                        "application/json"
                    ),
                },
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
                    min(
                        max(
                            wait,
                            1.0,
                        ),
                        30.0,
                    )
                )

                delay *= 2
                continue

            if response.status_code == 404:
                result = {
                    "domain": domain,
                    "status": "not_found",
                    "rdap_server": server,
                    "fetched_at": utc_now(),
                    "http_status": 404,
                    "error": None,
                }

                save_cached(
                    result
                )

                return result

            response.raise_for_status()

            payload = response.json()

            registration = event_date(
                payload,
                {
                    "registration",
                    "registered",
                },
            )

            expiration = event_date(
                payload,
                {
                    "expiration",
                    "expiry",
                },
            )

            changed = event_date(
                payload,
                {
                    "last changed",
                    "last update of rdap database",
                    "last update",
                },
            )

            age_days = None

            registration_dt = parse_datetime(
                registration
            )

            if registration_dt:
                age_days = max(
                    0,
                    (
                        datetime.now(
                            timezone.utc
                        )
                        - registration_dt
                    ).days,
                )

            result = {
                "domain": domain,
                "status": "success",
                "rdap_server": server,
                "registration_date": (
                    registration
                ),
                "expiration_date": (
                    expiration
                ),
                "last_changed_date": (
                    changed
                ),
                "registrar_name": (
                    registrar_name(
                        payload
                    )
                ),
                "domain_age_days": (
                    age_days
                ),
                "fetched_at": utc_now(),
                "http_status": (
                    response.status_code
                ),
                "response_json": payload,
                "error": None,
                "cache_hit": False,
            }

            save_cached(
                result
            )

            return result

        except requests.RequestException as error:
            if (
                attempt
                == maximum_attempts - 1
            ):
                result = {
                    "domain": domain,
                    "status": "error",
                    "rdap_server": server,
                    "fetched_at": utc_now(),
                    "error": repr(
                        error
                    ),
                }

                save_cached(
                    result
                )

                return result

            time.sleep(
                delay
            )

            delay *= 2

    raise RuntimeError(
        "Unexpected RDAP control flow."
    )
