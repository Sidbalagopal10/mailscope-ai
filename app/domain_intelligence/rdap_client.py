from __future__ import annotations

import ipaddress
import json
import sqlite3
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IANA_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)

DATABASE_PATH = Path(
    "data/domain_intelligence/domain_intelligence.db"
)

USER_AGENT = (
    "AI-Email-Security-Platform/1.0 "
    "(local research project)"
)

DEFAULT_TIMEOUT = 25


class RdapLookupError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_domain(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip().lower()

    if not cleaned:
        raise RdapLookupError(
            "A domain is required."
        )

    if "://" in cleaned:
        parsed = urllib.parse.urlparse(
            cleaned
        )

        cleaned = (
            parsed.hostname
            or ""
        )

    cleaned = (
        cleaned.split("/")[0]
        .split(":")[0]
        .rstrip(".")
    )

    if cleaned.startswith("www."):
        cleaned = cleaned[4:]

    if (
        not cleaned
        or "." not in cleaned
        or " " in cleaned
        or "@" in cleaned
    ):
        raise RdapLookupError(
            "Enter a complete domain such as example.org."
        )

    try:
        ipaddress.ip_address(
            cleaned
        )

    except ValueError:
        pass

    else:
        raise RdapLookupError(
            "RDAP domain lookup does not accept IP addresses."
        )

    try:
        ascii_domain = cleaned.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise RdapLookupError(
            "The domain could not be converted to IDNA."
        ) from error

    return ascii_domain


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS rdap_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                tld TEXT NOT NULL,
                rdap_server TEXT,
                lookup_status TEXT NOT NULL,
                registration_date TEXT,
                last_changed_date TEXT,
                expiration_date TEXT,
                registrar_name TEXT,
                registrar_handle TEXT,
                domain_age_days INTEGER,
                dnssec_state TEXT,
                domain_status_json TEXT NOT NULL,
                nameservers_json TEXT NOT NULL,
                events_json TEXT NOT NULL,
                entities_json TEXT NOT NULL,
                raw_response_json TEXT,
                error_message TEXT,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_rdap_domain
            ON rdap_observations(domain);

            CREATE INDEX IF NOT EXISTS
            idx_rdap_lookup_status
            ON rdap_observations(lookup_status);

            CREATE INDEX IF NOT EXISTS
            idx_rdap_registration_date
            ON rdap_observations(registration_date);
            """
        )

        connection.commit()


def request_json(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": (
                "application/rdap+json, "
                "application/json"
            ),
            "User-Agent": USER_AGENT,
        },
    )

    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=context,
        ) as response:
            payload = json.load(
                response
            )

    except urllib.error.HTTPError as error:
        raise RdapLookupError(
            f"RDAP server returned HTTP {error.code}."
        ) from error

    except urllib.error.URLError as error:
        raise RdapLookupError(
            f"Unable to contact RDAP service: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise RdapLookupError(
            "RDAP request timed out."
        ) from error

    except json.JSONDecodeError as error:
        raise RdapLookupError(
            "RDAP service returned invalid JSON."
        ) from error

    if not isinstance(
        payload,
        dict,
    ):
        raise RdapLookupError(
            "RDAP service returned an unsupported response."
        )

    return payload


def load_bootstrap_registry(
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    payload = request_json(
        IANA_BOOTSTRAP_URL,
        timeout=timeout,
    )

    services = payload.get(
        "services"
    )

    if not isinstance(
        services,
        list,
    ):
        raise RdapLookupError(
            "IANA RDAP bootstrap registry is malformed."
        )

    return payload


def resolve_rdap_server(
    domain: str,
    *,
    bootstrap: dict[str, Any] | None = None,
) -> str:
    normalized = normalize_domain(
        domain
    )

    tld = normalized.rsplit(
        ".",
        1,
    )[-1]

    registry = (
        bootstrap
        or load_bootstrap_registry()
    )

    for service in registry.get(
        "services",
        [],
    ):
        if (
            not isinstance(service, list)
            or len(service) != 2
        ):
            continue

        tlds, server_urls = service

        normalized_tlds = {
            str(item).lower()
            for item in (
                tlds
                if isinstance(tlds, list)
                else []
            )
        }

        if tld not in normalized_tlds:
            continue

        if not isinstance(
            server_urls,
            list,
        ):
            break

        for candidate in server_urls:
            candidate = str(
                candidate or ""
            ).strip()

            if candidate.startswith(
                "https://"
            ):
                return candidate.rstrip("/")

        for candidate in server_urls:
            candidate = str(
                candidate or ""
            ).strip()

            if candidate:
                return candidate.rstrip("/")

    raise RdapLookupError(
        f"No RDAP bootstrap service is registered for .{tld}."
    )


def parse_datetime(
    value: Any,
) -> datetime | None:
    if not value:
        return None

    text = str(
        value
    ).strip()

    if not text:
        return None

    normalized = text.replace(
        "Z",
        "+00:00",
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )

    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def extract_events(
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    result = []

    for item in payload.get(
        "events",
        [],
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        result.append(
            {
                "action": item.get(
                    "eventAction"
                ),
                "date": item.get(
                    "eventDate"
                ),
                "actor": item.get(
                    "eventActor"
                ),
            }
        )

    return result


def event_date(
    events: list[dict[str, Any]],
    actions: set[str],
) -> str | None:
    candidates = []

    for event in events:
        action = str(
            event.get(
                "action",
                "",
            )
        ).strip().lower()

        if action not in actions:
            continue

        parsed = parse_datetime(
            event.get(
                "date"
            )
        )

        if parsed is not None:
            candidates.append(
                parsed
            )

    if not candidates:
        return None

    selected = min(
        candidates
    )

    return selected.isoformat()


def extract_vcard_name(
    entity: dict[str, Any],
) -> str | None:
    vcard = entity.get(
        "vcardArray"
    )

    if (
        not isinstance(vcard, list)
        or len(vcard) != 2
        or not isinstance(vcard[1], list)
    ):
        return None

    for entry in vcard[1]:
        if (
            not isinstance(entry, list)
            or len(entry) < 4
        ):
            continue

        field_name = str(
            entry[0]
        ).lower()

        if field_name in {
            "fn",
            "org",
        }:
            value = entry[3]

            if isinstance(
                value,
                list,
            ):
                value = " ".join(
                    str(part)
                    for part in value
                    if part
                )

            cleaned = str(
                value or ""
            ).strip()

            if cleaned:
                return cleaned

    return None


def extract_entities(
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    result = []

    for entity in payload.get(
        "entities",
        [],
    ):
        if not isinstance(
            entity,
            dict,
        ):
            continue

        result.append(
            {
                "handle": entity.get(
                    "handle"
                ),
                "roles": entity.get(
                    "roles",
                    [],
                ),
                "name": extract_vcard_name(
                    entity
                ),
                "public_ids": entity.get(
                    "publicIds",
                    [],
                ),
            }
        )

    return result


def extract_registrar(
    entities: list[dict[str, Any]],
) -> tuple[
    str | None,
    str | None,
]:
    for entity in entities:
        roles = {
            str(role).lower()
            for role in entity.get(
                "roles",
                [],
            )
        }

        if "registrar" not in roles:
            continue

        return (
            entity.get(
                "name"
            ),
            entity.get(
                "handle"
            ),
        )

    return (
        None,
        None,
    )


def extract_nameservers(
    payload: dict[str, Any],
) -> list[str]:
    nameservers = set()

    for item in payload.get(
        "nameservers",
        [],
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        name = (
            item.get(
                "ldhName"
            )
            or item.get(
                "unicodeName"
            )
        )

        if name:
            nameservers.add(
                str(
                    name
                ).lower().rstrip(".")
            )

    return sorted(
        nameservers
    )


def calculate_domain_age_days(
    registration_date: str | None,
) -> int | None:
    parsed = parse_datetime(
        registration_date
    )

    if parsed is None:
        return None

    now = datetime.now(
        timezone.utc
    )

    delta = now - parsed

    if delta.days < 0:
        return None

    return int(
        delta.days
    )


def analyze_rdap_payload(
    *,
    domain: str,
    rdap_server: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    events = extract_events(
        payload
    )

    registration_date = event_date(
        events,
        {
            "registration",
            "registered",
        },
    )

    last_changed_date = event_date(
        events,
        {
            "last changed",
            "last update of rdap database",
            "changed",
            "updated",
        },
    )

    expiration_date = event_date(
        events,
        {
            "expiration",
            "expiry",
        },
    )

    entities = extract_entities(
        payload
    )

    registrar_name, registrar_handle = (
        extract_registrar(
            entities
        )
    )

    secure_dns = payload.get(
        "secureDNS"
    )

    if isinstance(
        secure_dns,
        dict,
    ):
        delegation_signed = secure_dns.get(
            "delegationSigned"
        )

        if delegation_signed is True:
            dnssec_state = "signed"

        elif delegation_signed is False:
            dnssec_state = "unsigned"

        else:
            dnssec_state = "unknown"

    else:
        dnssec_state = "unknown"

    statuses = sorted(
        {
            str(status)
            for status in payload.get(
                "status",
                []
            )
            if status
        }
    )

    return {
        "domain": normalize_domain(
            domain
        ),
        "tld": normalize_domain(
            domain
        ).rsplit(
            ".",
            1,
        )[-1],
        "rdap_server": rdap_server,
        "lookup_status": "success",
        "registration_date": registration_date,
        "last_changed_date": last_changed_date,
        "expiration_date": expiration_date,
        "registrar_name": registrar_name,
        "registrar_handle": registrar_handle,
        "domain_age_days": calculate_domain_age_days(
            registration_date
        ),
        "dnssec_state": dnssec_state,
        "domain_status": statuses,
        "nameservers": extract_nameservers(
            payload
        ),
        "events": events,
        "entities": entities,
        "raw_response": payload,
        "error_message": None,
        "observed_at": utc_now(),
    }


def save_observation(
    observation: dict[str, Any],
) -> dict[str, Any]:
    initialize_database()

    timestamp = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO rdap_observations (
                domain,
                tld,
                rdap_server,
                lookup_status,
                registration_date,
                last_changed_date,
                expiration_date,
                registrar_name,
                registrar_handle,
                domain_age_days,
                dnssec_state,
                domain_status_json,
                nameservers_json,
                events_json,
                entities_json,
                raw_response_json,
                error_message,
                observed_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(domain)
            DO UPDATE SET
                tld = excluded.tld,
                rdap_server = excluded.rdap_server,
                lookup_status = excluded.lookup_status,
                registration_date = excluded.registration_date,
                last_changed_date = excluded.last_changed_date,
                expiration_date = excluded.expiration_date,
                registrar_name = excluded.registrar_name,
                registrar_handle = excluded.registrar_handle,
                domain_age_days = excluded.domain_age_days,
                dnssec_state = excluded.dnssec_state,
                domain_status_json = excluded.domain_status_json,
                nameservers_json = excluded.nameservers_json,
                events_json = excluded.events_json,
                entities_json = excluded.entities_json,
                raw_response_json = excluded.raw_response_json,
                error_message = excluded.error_message,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at
            """,
            (
                observation["domain"],
                observation["tld"],
                observation.get(
                    "rdap_server"
                ),
                observation[
                    "lookup_status"
                ],
                observation.get(
                    "registration_date"
                ),
                observation.get(
                    "last_changed_date"
                ),
                observation.get(
                    "expiration_date"
                ),
                observation.get(
                    "registrar_name"
                ),
                observation.get(
                    "registrar_handle"
                ),
                observation.get(
                    "domain_age_days"
                ),
                observation.get(
                    "dnssec_state",
                    "unknown",
                ),
                json.dumps(
                    observation.get(
                        "domain_status",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "nameservers",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "events",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "entities",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "raw_response"
                    ),
                    sort_keys=True,
                )
                if observation.get(
                    "raw_response"
                )
                is not None
                else None,
                observation.get(
                    "error_message"
                ),
                observation.get(
                    "observed_at",
                    timestamp,
                ),
                timestamp,
            ),
        )

        connection.commit()

    saved = get_observation(
        observation["domain"]
    )

    if saved is None:
        raise RdapLookupError(
            "RDAP observation could not be saved."
        )

    return saved


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    mappings = {
        "domain_status_json": (
            "domain_status"
        ),
        "nameservers_json": "nameservers",
        "events_json": "events",
        "entities_json": "entities",
        "raw_response_json": "raw_response",
    }

    for source_key, destination_key in mappings.items():
        raw_value = result.pop(
            source_key,
            None,
        )

        if raw_value:
            try:
                result[destination_key] = json.loads(
                    raw_value
                )

            except json.JSONDecodeError:
                result[destination_key] = None

        else:
            result[destination_key] = (
                []
                if destination_key
                in {
                    "domain_status",
                    "nameservers",
                    "events",
                    "entities",
                }
                else None
            )

    return result


def get_observation(
    domain: str,
) -> dict[str, Any] | None:
    initialize_database()

    normalized = normalize_domain(
        domain
    )

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM rdap_observations
            WHERE domain = ?
            """,
            (
                normalized,
            ),
        ).fetchone()

    if row is None:
        return None

    return deserialize_row(
        row
    )


def lookup_domain(
    domain: str,
    *,
    force: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    normalized = normalize_domain(
        domain
    )

    if not force:
        cached = get_observation(
            normalized
        )

        if cached is not None:
            return {
                **cached,
                "cache_status": "cached",
            }

    try:
        server = resolve_rdap_server(
            normalized
        )

        lookup_url = (
            f"{server}/domain/"
            f"{urllib.parse.quote(normalized)}"
        )

        payload = request_json(
            lookup_url,
            timeout=timeout,
        )

        observation = analyze_rdap_payload(
            domain=normalized,
            rdap_server=server,
            payload=payload,
        )

    except Exception as error:
        observation = {
            "domain": normalized,
            "tld": normalized.rsplit(
                ".",
                1,
            )[-1],
            "rdap_server": None,
            "lookup_status": "failed",
            "registration_date": None,
            "last_changed_date": None,
            "expiration_date": None,
            "registrar_name": None,
            "registrar_handle": None,
            "domain_age_days": None,
            "dnssec_state": "unknown",
            "domain_status": [],
            "nameservers": [],
            "events": [],
            "entities": [],
            "raw_response": None,
            "error_message": str(
                error
            ),
            "observed_at": utc_now(),
        }

    saved = save_observation(
        observation
    )

    return {
        **saved,
        "cache_status": "fresh",
    }


def list_observations(
    limit: int = 500,
) -> list[dict[str, Any]]:
    initialize_database()

    safe_limit = max(
        1,
        min(
            int(limit),
            5000,
        ),
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM rdap_observations
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (
                safe_limit,
            ),
        ).fetchall()

    return [
        deserialize_row(
            row
        )
        for row in rows
    ]


def get_summary() -> dict[str, Any]:
    initialize_database()

    with get_connection() as connection:
        total = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM rdap_observations
            """
        ).fetchone()["count"]

        successful = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM rdap_observations
            WHERE lookup_status = 'success'
            """
        ).fetchone()["count"]

        newly_registered = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM rdap_observations
            WHERE domain_age_days IS NOT NULL
              AND domain_age_days <= 30
            """
        ).fetchone()["count"]

        dnssec_signed = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM rdap_observations
            WHERE dnssec_state = 'signed'
            """
        ).fetchone()["count"]

        tld_rows = connection.execute(
            """
            SELECT
                tld,
                COUNT(*) AS count
            FROM rdap_observations
            GROUP BY tld
            ORDER BY count DESC
            LIMIT 20
            """
        ).fetchall()

    return {
        "observed_domains": int(
            total
        ),
        "successful_lookups": int(
            successful
        ),
        "failed_lookups": int(
            total - successful
        ),
        "domains_age_30_days_or_less": int(
            newly_registered
        ),
        "dnssec_signed": int(
            dnssec_signed
        ),
        "top_tlds": {
            row["tld"]: int(
                row["count"]
            )
            for row in tld_rows
        },
    }
