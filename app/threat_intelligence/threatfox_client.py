from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


API_URL = (
    "https://threatfox-api.abuse.ch/api/v1/"
)

DATABASE_PATH = Path(
    "data/threat_intelligence/threatfox.db"
)

DEFAULT_TIMEOUT = 30

USER_AGENT = (
    "AI-Mail-Phishing-Detector/1.0 "
    "(defensive-security-research)"
)


class ThreatFoxError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def load_auth_key() -> str:
    load_dotenv(
        dotenv_path=Path(".env")
    )

    key = os.getenv(
        "ABUSECH_AUTH_KEY",
        "",
    ).strip()

    if not key:
        raise ThreatFoxError(
            "ABUSECH_AUTH_KEY is missing from .env."
        )

    return key


def normalize_indicator(
    value: str,
) -> dict[str, str]:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        raise ThreatFoxError(
            "An indicator is required."
        )

    if cleaned.startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = urllib.parse.urlparse(
            cleaned
        )

        if not parsed.hostname:
            raise ThreatFoxError(
                "The URL does not contain a hostname."
            )

        return {
            "indicator": cleaned,
            "indicator_type": "url",
            "hostname": (
                parsed.hostname
                .lower()
                .rstrip(".")
            ),
        }

    candidate = (
        cleaned.split("/")[0]
        .split(":")[0]
        .lower()
        .rstrip(".")
    )

    try:
        address = ipaddress.ip_address(
            candidate
        )

        return {
            "indicator": str(
                address
            ),
            "indicator_type": "ip",
            "hostname": "",
        }

    except ValueError:
        pass

    if (
        "." not in candidate
        or " " in candidate
        or "@" in candidate
    ):
        raise ThreatFoxError(
            "Enter a URL, domain, or IP address."
        )

    try:
        candidate = candidate.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise ThreatFoxError(
            "The domain could not be converted to IDNA."
        ) from error

    return {
        "indicator": candidate,
        "indicator_type": "domain",
        "hostname": candidate,
    }


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
            CREATE TABLE IF NOT EXISTS threatfox_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                indicator_type TEXT NOT NULL,
                hostname TEXT,
                lookup_status TEXT NOT NULL,
                query_status TEXT,
                matched INTEGER NOT NULL DEFAULT 0,
                match_count INTEGER NOT NULL DEFAULT 0,
                matches_json TEXT NOT NULL,
                malware_families_json TEXT NOT NULL,
                threat_types_json TEXT NOT NULL,
                maximum_confidence INTEGER,
                error_message TEXT,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_threatfox_matched
            ON threatfox_observations(matched);

            CREATE INDEX IF NOT EXISTS
            idx_threatfox_indicator_type
            ON threatfox_observations(indicator_type);
            """
        )

        connection.commit()


def request_json(
    payload: dict[str, Any],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    auth_key = load_auth_key()

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(
            payload
        ).encode(
            "utf-8"
        ),
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=context,
        ) as response:
            result = json.load(
                response
            )

    except urllib.error.HTTPError as error:
        body = error.read().decode(
            "utf-8",
            errors="replace",
        )

        raise ThreatFoxError(
            f"ThreatFox HTTP {error.code}: "
            f"{body[:300]}"
        ) from error

    except urllib.error.URLError as error:
        raise ThreatFoxError(
            "Unable to contact ThreatFox: "
            f"{error.reason}"
        ) from error

    except TimeoutError as error:
        raise ThreatFoxError(
            "ThreatFox request timed out."
        ) from error

    except json.JSONDecodeError as error:
        raise ThreatFoxError(
            "ThreatFox returned invalid JSON."
        ) from error

    if not isinstance(
        result,
        dict,
    ):
        raise ThreatFoxError(
            "ThreatFox returned an unsupported response."
        )

    return result


def search_ioc(
    indicator: str,
) -> dict[str, Any]:
    """
    Search ThreatFox for an exact or related IOC.

    ThreatFox's search_ioc query is used only for retrieval.
    No IOC is submitted by this project.
    """
    return request_json(
        {
            "query": "search_ioc",
            "search_term": indicator,
        }
    )


def normalize_match(
    match: dict[str, Any],
) -> dict[str, Any]:
    confidence = match.get(
        "confidence_level"
    )

    try:
        confidence_value = int(
            confidence
        )

    except (
        TypeError,
        ValueError,
    ):
        confidence_value = 0

    tags = match.get(
        "tags"
    )

    if not isinstance(
        tags,
        list,
    ):
        tags = []

    return {
        "id": match.get(
            "id"
        ),
        "ioc": match.get(
            "ioc"
        ),
        "ioc_type": match.get(
            "ioc_type"
        ),
        "ioc_type_desc": match.get(
            "ioc_type_desc"
        ),
        "threat_type": match.get(
            "threat_type"
        ),
        "threat_type_desc": match.get(
            "threat_type_desc"
        ),
        "malware": match.get(
            "malware"
        ),
        "malware_printable": match.get(
            "malware_printable"
        ),
        "confidence_level": (
            confidence_value
        ),
        "first_seen": match.get(
            "first_seen"
        ),
        "last_seen": match.get(
            "last_seen"
        ),
        "reporter": match.get(
            "reporter"
        ),
        "reference": match.get(
            "reference"
        ),
        "tags": tags,
    }


def normalize_url_for_comparison(
    value: str,
) -> str | None:
    """
    Normalize an HTTP or HTTPS URL without contacting it.
    """
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return None

    parsed = urllib.parse.urlsplit(
        cleaned
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    if not hostname:
        return None

    try:
        hostname = hostname.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError:
        return None

    scheme = parsed.scheme.lower()

    port = parsed.port

    default_port = (
        scheme == "http"
        and port == 80
    ) or (
        scheme == "https"
        and port == 443
    )

    network_location = hostname

    if (
        port is not None
        and not default_port
    ):
        network_location = (
            f"{hostname}:{port}"
        )

    path = parsed.path or "/"

    return urllib.parse.urlunsplit(
        (
            scheme,
            network_location,
            path,
            parsed.query,
            "",
        )
    )


def extract_ioc_hostname(
    value: str,
) -> str | None:
    """
    Extract an exact hostname from a ThreatFox IOC.

    Supports domains, URLs and host:port indicators. It does not
    use substring or fuzzy matching.
    """
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return None

    if cleaned.startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = urllib.parse.urlsplit(
            cleaned
        )

        hostname = parsed.hostname

    else:
        candidate = cleaned

        # Remove URL paths from domain-style values.
        candidate = candidate.split(
            "/",
            1,
        )[0]

        # Handle bracketed IPv6 values.
        if candidate.startswith("["):
            closing = candidate.find("]")

            hostname = (
                candidate[
                    1:closing
                ]
                if closing != -1
                else candidate
            )

        else:
            try:
                ipaddress.ip_address(
                    candidate
                )

                hostname = candidate

            except ValueError:
                # Remove a numeric port without damaging IPv6.
                if (
                    candidate.count(":") == 1
                    and candidate.rsplit(
                        ":",
                        1,
                    )[1].isdigit()
                ):
                    candidate = candidate.rsplit(
                        ":",
                        1,
                    )[0]

                hostname = candidate

    if not hostname:
        return None

    hostname = str(
        hostname
    ).lower().rstrip(".")

    try:
        return hostname.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError:
        return None


def hosts_are_related(
    query_host: str,
    ioc_host: str,
) -> bool:
    """
    Accept only exact hostname or true subdomain relationships.

    Accepted:
        microsoft.com
        login.microsoft.com

    Rejected:
        m.s-microsoft.com
        microsoft-login.com
        fake-microsoft.com
    """
    query = str(
        query_host or ""
    ).lower().rstrip(".")

    ioc = str(
        ioc_host or ""
    ).lower().rstrip(".")

    if not query or not ioc:
        return False

    try:
        query_ip = ipaddress.ip_address(
            query
        )

        ioc_ip = ipaddress.ip_address(
            ioc
        )

        return query_ip == ioc_ip

    except ValueError:
        pass

    return bool(
        query == ioc
        or query.endswith(
            f".{ioc}"
        )
        or ioc.endswith(
            f".{query}"
        )
    )


def response_match_is_relevant(
    *,
    indicator_data: dict[str, str],
    match: dict[str, Any],
) -> bool:
    """
    Verify that a ThreatFox search result refers to the submitted
    indicator—not merely a similar string returned by search_ioc.
    """
    submitted_indicator = indicator_data.get(
        "indicator",
        "",
    )

    submitted_type = indicator_data.get(
        "indicator_type",
        "",
    )

    submitted_host = (
        indicator_data.get(
            "hostname"
        )
        or extract_ioc_hostname(
            submitted_indicator
        )
    )

    returned_ioc = str(
        match.get(
            "ioc",
            "",
        )
        or ""
    ).strip()

    if not returned_ioc:
        return False

    submitted_url = normalize_url_for_comparison(
        submitted_indicator
    )

    returned_url = normalize_url_for_comparison(
        returned_ioc
    )

    # Exact normalized URL match is authoritative.
    if (
        submitted_url is not None
        and returned_url is not None
        and submitted_url == returned_url
    ):
        return True

    returned_host = extract_ioc_hostname(
        returned_ioc
    )

    if (
        not submitted_host
        or not returned_host
    ):
        return False

    # For IP searches, require exact equality.
    if submitted_type == "ip":
        return submitted_host == returned_host

    return hosts_are_related(
        submitted_host,
        returned_host,
    )


def summarize_response(
    *,
    indicator_data: dict[str, str],
    response: dict[str, Any],
) -> dict[str, Any]:
    query_status = str(
        response.get(
            "query_status",
            "",
        )
        or ""
    ).lower()

    raw_data = response.get(
        "data"
    )

    all_matches = []

    if isinstance(
        raw_data,
        list,
    ):
        all_matches = [
            match
            for match in raw_data
            if isinstance(
                match,
                dict,
            )
        ]

    # ThreatFox search_ioc can return similar indicators. Apply
    # strict hostname/subdomain validation before adding risk.
    relevant_raw_matches = [
        match
        for match in all_matches
        if response_match_is_relevant(
            indicator_data=indicator_data,
            match=match,
        )
    ]

    matches = [
        normalize_match(
            match
        )
        for match in relevant_raw_matches
    ]

    ignored_matches = [
        normalize_match(
            match
        )
        for match in all_matches
        if match not in relevant_raw_matches
    ]

    matched = bool(
        query_status == "ok"
        and matches
    )

    malware_families = sorted(
        {
            str(
                match.get(
                    "malware_printable"
                )
                or match.get(
                    "malware"
                )
            ).strip()
            for match in matches
            if (
                match.get(
                    "malware_printable"
                )
                or match.get(
                    "malware"
                )
            )
        }
    )

    threat_types = sorted(
        {
            str(
                match.get(
                    "threat_type"
                )
            ).strip()
            for match in matches
            if match.get(
                "threat_type"
            )
        }
    )

    maximum_confidence = max(
        (
            int(
                match.get(
                    "confidence_level",
                    0,
                )
                or 0
            )
            for match in matches
        ),
        default=0,
    )

    effective_query_status = query_status

    if (
        query_status == "ok"
        and not matches
    ):
        effective_query_status = (
            "no_exact_match"
        )

    return {
        **indicator_data,
        "lookup_status": "success",
        "query_status": (
            effective_query_status
        ),
        "matched": matched,
        "match_count": len(
            matches
        ),
        "matches": matches,
        "ignored_match_count": len(
            ignored_matches
        ),
        "ignored_matches": (
            ignored_matches
        ),
        "malware_families": (
            malware_families
        ),
        "threat_types": threat_types,
        "maximum_confidence": (
            maximum_confidence
        ),
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
            INSERT INTO threatfox_observations (
                indicator,
                indicator_type,
                hostname,
                lookup_status,
                query_status,
                matched,
                match_count,
                matches_json,
                malware_families_json,
                threat_types_json,
                maximum_confidence,
                error_message,
                observed_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(indicator)
            DO UPDATE SET
                indicator_type = excluded.indicator_type,
                hostname = excluded.hostname,
                lookup_status = excluded.lookup_status,
                query_status = excluded.query_status,
                matched = excluded.matched,
                match_count = excluded.match_count,
                matches_json = excluded.matches_json,
                malware_families_json =
                    excluded.malware_families_json,
                threat_types_json = excluded.threat_types_json,
                maximum_confidence = excluded.maximum_confidence,
                error_message = excluded.error_message,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at
            """,
            (
                observation[
                    "indicator"
                ],
                observation[
                    "indicator_type"
                ],
                observation.get(
                    "hostname"
                ),
                observation[
                    "lookup_status"
                ],
                observation.get(
                    "query_status"
                ),
                int(
                    observation.get(
                        "matched",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "match_count",
                        0,
                    )
                ),
                json.dumps(
                    observation.get(
                        "matches",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "malware_families",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "threat_types",
                        [],
                    ),
                    sort_keys=True,
                ),
                observation.get(
                    "maximum_confidence"
                ),
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
        observation[
            "indicator"
        ]
    )

    if saved is None:
        raise ThreatFoxError(
            "ThreatFox observation could not be saved."
        )

    return saved


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    mappings = {
        "matches_json": "matches",
        "malware_families_json": (
            "malware_families"
        ),
        "threat_types_json": (
            "threat_types"
        ),
    }

    for source, destination in mappings.items():
        raw = result.pop(
            source,
            None,
        )

        try:
            result[
                destination
            ] = (
                json.loads(
                    raw
                )
                if raw
                else []
            )

        except json.JSONDecodeError:
            result[
                destination
            ] = []

    result["matched"] = bool(
        result.get(
            "matched"
        )
    )

    return result


def get_observation(
    indicator: str,
) -> dict[str, Any] | None:
    initialize_database()

    normalized = normalize_indicator(
        indicator
    )[
        "indicator"
    ]

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM threatfox_observations
            WHERE indicator = ?
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


def lookup_indicator(
    indicator: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    indicator_data = normalize_indicator(
        indicator
    )

    normalized = indicator_data[
        "indicator"
    ]

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
        response = search_ioc(
            normalized
        )

        observation = summarize_response(
            indicator_data=(
                indicator_data
            ),
            response=response,
        )

    except Exception as error:
        observation = {
            **indicator_data,
            "lookup_status": "failed",
            "query_status": None,
            "matched": False,
            "match_count": 0,
            "matches": [],
            "malware_families": [],
            "threat_types": [],
            "maximum_confidence": 0,
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
            int(
                limit
            ),
            5000,
        ),
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM threatfox_observations
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
            FROM threatfox_observations
            """
        ).fetchone()["count"]

        matched = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM threatfox_observations
            WHERE matched = 1
            """
        ).fetchone()["count"]

        failed = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM threatfox_observations
            WHERE lookup_status = 'failed'
            """
        ).fetchone()["count"]

    return {
        "observed_indicators": int(
            total
        ),
        "matched_indicators": int(
            matched
        ),
        "clean_or_unmatched": int(
            total - matched - failed
        ),
        "failed_lookups": int(
            failed
        ),
    }
