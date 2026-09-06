from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


API_BASE_URL = "https://www.virustotal.com/api/v3"

DATABASE_PATH = Path(
    "data/threat_intelligence/virustotal.db"
)

CACHE_HOURS = 24
REQUEST_TIMEOUT = 30
MINIMUM_REQUEST_INTERVAL = 16.0

USER_AGENT = (
    "AI-Mail-Phishing-Detector/1.0 "
    "(defensive-security-research)"
)

_last_request_time = 0.0


class VirusTotalError(Exception):
    pass


class VirusTotalQuotaError(VirusTotalError):
    pass


class VirusTotalNotFound(VirusTotalError):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def load_api_key() -> str:
    load_dotenv(
        dotenv_path=Path(".env")
    )

    key = os.getenv(
        "VIRUSTOTAL_API_KEY",
        "",
    ).strip()

    if not key:
        raise VirusTotalError(
            "VIRUSTOTAL_API_KEY is missing from .env."
        )

    return key


def normalize_hostname(
    value: str,
) -> str:
    hostname = str(
        value or ""
    ).strip().lower().rstrip(".")

    if not hostname:
        raise VirusTotalError(
            "A hostname is required."
        )

    try:
        return hostname.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise VirusTotalError(
            "The hostname could not be converted to IDNA."
        ) from error


def normalize_url(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    parsed = urllib.parse.urlsplit(
        cleaned
    )

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise VirusTotalError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise VirusTotalError(
            "The URL does not contain a hostname."
        )

    hostname = normalize_hostname(
        parsed.hostname
    )

    scheme = parsed.scheme.lower()

    try:
        port = parsed.port

    except ValueError as error:
        raise VirusTotalError(
            "The URL contains an invalid port."
        ) from error

    default_port = bool(
        (
            scheme == "http"
            and port == 80
        )
        or (
            scheme == "https"
            and port == 443
        )
    )

    network_location = hostname

    if port is not None and not default_port:
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


def url_identifier(
    url: str,
) -> str:
    normalized = normalize_url(
        url
    )

    return base64.urlsafe_b64encode(
        normalized.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    ).rstrip("=")


def normalize_indicator(
    value: str,
) -> dict[str, str]:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        raise VirusTotalError(
            "A URL, domain, or IP address is required."
        )

    if cleaned.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):
        normalized_url = normalize_url(
            cleaned
        )

        hostname = (
            urllib.parse.urlsplit(
                normalized_url
            ).hostname
            or ""
        )

        return {
            "indicator": normalized_url,
            "indicator_type": "url",
            "hostname": hostname,
        }

    candidate = cleaned.lower().rstrip(".")

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

    hostname = normalize_hostname(
        candidate
    )

    if "." not in hostname:
        raise VirusTotalError(
            "Enter a complete domain, URL, or IP address."
        )

    return {
        "indicator": hostname,
        "indicator_type": "domain",
        "hostname": hostname,
    }


def cache_key(
    indicator_type: str,
    indicator: str,
) -> str:
    return hashlib.sha256(
        (
            f"{indicator_type}:"
            f"{indicator}"
        ).encode(
            "utf-8"
        )
    ).hexdigest()


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
            CREATE TABLE IF NOT EXISTS virustotal_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key TEXT NOT NULL UNIQUE,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                hostname TEXT,
                lookup_status TEXT NOT NULL,
                object_found INTEGER NOT NULL DEFAULT 0,
                malicious INTEGER NOT NULL DEFAULT 0,
                suspicious INTEGER NOT NULL DEFAULT 0,
                harmless INTEGER NOT NULL DEFAULT 0,
                undetected INTEGER NOT NULL DEFAULT 0,
                timeout_count INTEGER NOT NULL DEFAULT 0,
                failure INTEGER NOT NULL DEFAULT 0,
                total_engines INTEGER NOT NULL DEFAULT 0,
                malicious_ratio REAL NOT NULL DEFAULT 0,
                reputation INTEGER,
                categories_json TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                last_analysis_date TEXT,
                raw_summary_json TEXT NOT NULL,
                error_message TEXT,
                observed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_virustotal_indicator
            ON virustotal_observations(
                indicator_type,
                indicator
            );

            CREATE INDEX IF NOT EXISTS
            idx_virustotal_expiry
            ON virustotal_observations(
                expires_at
            );
            """
        )

        connection.commit()


def throttle_request() -> None:
    global _last_request_time

    elapsed = (
        time.monotonic()
        - _last_request_time
    )

    remaining = (
        MINIMUM_REQUEST_INTERVAL
        - elapsed
    )

    if remaining > 0:
        time.sleep(
            remaining
        )

    _last_request_time = (
        time.monotonic()
    )


def request_json(
    endpoint: str,
) -> dict[str, Any]:
    throttle_request()

    key = load_api_key()

    request = urllib.request.Request(
        f"{API_BASE_URL}{endpoint}",
        headers={
            "x-apikey": key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:
            payload = json.load(
                response
            )

    except urllib.error.HTTPError as error:
        body = error.read().decode(
            "utf-8",
            errors="replace",
        )

        if error.code == 404:
            raise VirusTotalNotFound(
                "VirusTotal has no report for this indicator."
            ) from error

        if error.code == 429:
            raise VirusTotalQuotaError(
                "VirusTotal quota or rate limit was reached."
            ) from error

        if error.code in {
            401,
            403,
        }:
            raise VirusTotalError(
                "VirusTotal rejected the API key or permission."
            ) from error

        raise VirusTotalError(
            f"VirusTotal HTTP {error.code}: "
            f"{body[:300]}"
        ) from error

    except urllib.error.URLError as error:
        raise VirusTotalError(
            "Unable to contact VirusTotal: "
            f"{error.reason}"
        ) from error

    except TimeoutError as error:
        raise VirusTotalError(
            "VirusTotal request timed out."
        ) from error

    except json.JSONDecodeError as error:
        raise VirusTotalError(
            "VirusTotal returned invalid JSON."
        ) from error

    if not isinstance(
        payload,
        dict,
    ):
        raise VirusTotalError(
            "VirusTotal returned an unsupported response."
        )

    return payload


def object_endpoint(
    indicator_data: dict[str, str],
) -> str:
    indicator_type = indicator_data[
        "indicator_type"
    ]

    indicator = indicator_data[
        "indicator"
    ]

    if indicator_type == "url":
        return (
            "/urls/"
            + url_identifier(
                indicator
            )
        )

    if indicator_type == "domain":
        return (
            "/domains/"
            + urllib.parse.quote(
                indicator,
                safe="",
            )
        )

    if indicator_type == "ip":
        return (
            "/ip_addresses/"
            + urllib.parse.quote(
                indicator,
                safe="",
            )
        )

    raise VirusTotalError(
        "Unsupported indicator type."
    )


def parse_timestamp(
    value: Any,
) -> str | None:
    try:
        timestamp = int(
            value
        )

    except (
        TypeError,
        ValueError,
    ):
        return None

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def normalize_string_list(
    value: Any,
) -> list[str]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return sorted(
        {
            str(
                item
            ).strip()
            for item in value
            if str(
                item
            ).strip()
        }
    )


def normalize_categories(
    value: Any,
) -> list[str]:
    if not isinstance(
        value,
        dict,
    ):
        return []

    return sorted(
        {
            str(
                category
            ).strip()
            for category in value.values()
            if str(
                category
            ).strip()
        }
    )


def summarize_payload(
    *,
    indicator_data: dict[str, str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    data = payload.get(
        "data",
        {},
    )

    if not isinstance(
        data,
        dict,
    ):
        data = {}

    attributes = data.get(
        "attributes",
        {},
    )

    if not isinstance(
        attributes,
        dict,
    ):
        attributes = {}

    stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    if not isinstance(
        stats,
        dict,
    ):
        stats = {}

    def stat(
        name: str,
    ) -> int:
        try:
            return max(
                0,
                int(
                    stats.get(
                        name,
                        0,
                    )
                    or 0
                ),
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0

    malicious = stat(
        "malicious"
    )

    suspicious = stat(
        "suspicious"
    )

    harmless = stat(
        "harmless"
    )

    undetected = stat(
        "undetected"
    )

    timeout_count = stat(
        "timeout"
    )

    failure = stat(
        "failure"
    )

    type_unsupported = stat(
        "type-unsupported"
    )

    confirmed_timeout = stat(
        "confirmed-timeout"
    )

    total_engines = sum(
        [
            malicious,
            suspicious,
            harmless,
            undetected,
            timeout_count,
            failure,
            type_unsupported,
            confirmed_timeout,
        ]
    )

    malicious_ratio = (
        (
            malicious
            + suspicious * 0.5
        )
        / total_engines
        if total_engines
        else 0.0
    )

    reputation = attributes.get(
        "reputation"
    )

    try:
        normalized_reputation = int(
            reputation
        )

    except (
        TypeError,
        ValueError,
    ):
        normalized_reputation = None

    categories = normalize_categories(
        attributes.get(
            "categories"
        )
    )

    tags = normalize_string_list(
        attributes.get(
            "tags"
        )
    )

    return {
        **indicator_data,
        "lookup_status": "success",
        "object_found": True,
        "virustotal_object_id": data.get(
            "id"
        ),
        "virustotal_object_type": data.get(
            "type"
        ),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout_count": timeout_count,
        "failure": failure,
        "total_engines": total_engines,
        "malicious_ratio": round(
            malicious_ratio,
            6,
        ),
        "reputation": (
            normalized_reputation
        ),
        "categories": categories,
        "tags": tags,
        "last_analysis_date": (
            parse_timestamp(
                attributes.get(
                    "last_analysis_date"
                )
            )
        ),
        "raw_summary": {
            "last_analysis_stats": stats,
            "times_submitted": attributes.get(
                "times_submitted"
            ),
            "last_submission_date": (
                parse_timestamp(
                    attributes.get(
                        "last_submission_date"
                    )
                )
            ),
            "first_submission_date": (
                parse_timestamp(
                    attributes.get(
                        "first_submission_date"
                    )
                )
            ),
            "last_modification_date": (
                parse_timestamp(
                    attributes.get(
                        "last_modification_date"
                    )
                )
            ),
        },
        "error_message": None,
        "observed_at": utc_now(),
    }


def no_report_observation(
    indicator_data: dict[str, str],
) -> dict[str, Any]:
    return {
        **indicator_data,
        "lookup_status": "success",
        "object_found": False,
        "virustotal_object_id": None,
        "virustotal_object_type": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout_count": 0,
        "failure": 0,
        "total_engines": 0,
        "malicious_ratio": 0.0,
        "reputation": None,
        "categories": [],
        "tags": [],
        "last_analysis_date": None,
        "raw_summary": {},
        "error_message": None,
        "observed_at": utc_now(),
    }


def failed_observation(
    indicator_data: dict[str, str],
    error: Exception,
) -> dict[str, Any]:
    return {
        **indicator_data,
        "lookup_status": "failed",
        "object_found": False,
        "virustotal_object_id": None,
        "virustotal_object_type": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout_count": 0,
        "failure": 0,
        "total_engines": 0,
        "malicious_ratio": 0.0,
        "reputation": None,
        "categories": [],
        "tags": [],
        "last_analysis_date": None,
        "raw_summary": {},
        "error_message": str(
            error
        ),
        "observed_at": utc_now(),
    }


def expiry_time() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        + timedelta(
            hours=CACHE_HOURS
        )
    ).isoformat()


def save_observation(
    observation: dict[str, Any],
) -> dict[str, Any]:
    initialize_database()

    timestamp = utc_now()

    key = cache_key(
        observation[
            "indicator_type"
        ],
        observation[
            "indicator"
        ],
    )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO virustotal_observations (
                cache_key,
                indicator,
                indicator_type,
                hostname,
                lookup_status,
                object_found,
                malicious,
                suspicious,
                harmless,
                undetected,
                timeout_count,
                failure,
                total_engines,
                malicious_ratio,
                reputation,
                categories_json,
                tags_json,
                last_analysis_date,
                raw_summary_json,
                error_message,
                observed_at,
                expires_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(cache_key)
            DO UPDATE SET
                indicator = excluded.indicator,
                indicator_type = excluded.indicator_type,
                hostname = excluded.hostname,
                lookup_status = excluded.lookup_status,
                object_found = excluded.object_found,
                malicious = excluded.malicious,
                suspicious = excluded.suspicious,
                harmless = excluded.harmless,
                undetected = excluded.undetected,
                timeout_count = excluded.timeout_count,
                failure = excluded.failure,
                total_engines = excluded.total_engines,
                malicious_ratio = excluded.malicious_ratio,
                reputation = excluded.reputation,
                categories_json = excluded.categories_json,
                tags_json = excluded.tags_json,
                last_analysis_date = excluded.last_analysis_date,
                raw_summary_json = excluded.raw_summary_json,
                error_message = excluded.error_message,
                observed_at = excluded.observed_at,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            """,
            (
                key,
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
                int(
                    observation.get(
                        "object_found",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "malicious",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "suspicious",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "harmless",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "undetected",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "timeout_count",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "failure",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "total_engines",
                        0,
                    )
                ),
                float(
                    observation.get(
                        "malicious_ratio",
                        0.0,
                    )
                ),
                observation.get(
                    "reputation"
                ),
                json.dumps(
                    observation.get(
                        "categories",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "tags",
                        [],
                    ),
                    sort_keys=True,
                ),
                observation.get(
                    "last_analysis_date"
                ),
                json.dumps(
                    observation.get(
                        "raw_summary",
                        {},
                    ),
                    sort_keys=True,
                ),
                observation.get(
                    "error_message"
                ),
                observation.get(
                    "observed_at",
                    timestamp,
                ),
                expiry_time(),
                timestamp,
            ),
        )

        connection.commit()

    result = get_cached_observation(
        observation[
            "indicator_type"
        ],
        observation[
            "indicator"
        ],
        include_expired=True,
    )

    if result is None:
        raise VirusTotalError(
            "VirusTotal observation could not be saved."
        )

    return result


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    for source, destination, default in [
        (
            "categories_json",
            "categories",
            [],
        ),
        (
            "tags_json",
            "tags",
            [],
        ),
        (
            "raw_summary_json",
            "raw_summary",
            {},
        ),
    ]:
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
                else default
            )

        except json.JSONDecodeError:
            result[
                destination
            ] = default

    result[
        "object_found"
    ] = bool(
        result.get(
            "object_found"
        )
    )

    return result


def get_cached_observation(
    indicator_type: str,
    indicator: str,
    *,
    include_expired: bool = False,
) -> dict[str, Any] | None:
    initialize_database()

    key = cache_key(
        indicator_type,
        indicator,
    )

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM virustotal_observations
            WHERE cache_key = ?
            """,
            (
                key,
            ),
        ).fetchone()

    if row is None:
        return None

    result = deserialize_row(
        row
    )

    if include_expired:
        return result

    try:
        expires_at = datetime.fromisoformat(
            result[
                "expires_at"
            ]
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None

    if expires_at <= datetime.now(
        timezone.utc
    ):
        return None

    return result


def lookup_indicator(
    value: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    indicator_data = normalize_indicator(
        value
    )

    indicator = indicator_data[
        "indicator"
    ]

    indicator_type = indicator_data[
        "indicator_type"
    ]

    if not force:
        cached = get_cached_observation(
            indicator_type,
            indicator,
        )

        if cached is not None:
            return {
                **cached,
                "cache_status": "cached",
            }

    try:
        payload = request_json(
            object_endpoint(
                indicator_data
            )
        )

        observation = summarize_payload(
            indicator_data=(
                indicator_data
            ),
            payload=payload,
        )

    except VirusTotalNotFound:
        observation = no_report_observation(
            indicator_data
        )

    except Exception as error:
        stale = get_cached_observation(
            indicator_type,
            indicator,
            include_expired=True,
        )

        if stale is not None:
            return {
                **stale,
                "cache_status": "stale_fallback",
                "refresh_error": str(
                    error
                ),
            }

        observation = failed_observation(
            indicator_data,
            error,
        )

    saved = save_observation(
        observation
    )

    return {
        **saved,
        "cache_status": "fresh",
    }


def lookup_url_and_domain(
    url: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    normalized_url = normalize_url(
        url
    )

    hostname = (
        urllib.parse.urlsplit(
            normalized_url
        ).hostname
        or ""
    )

    url_result = lookup_indicator(
        normalized_url,
        force=force,
    )

    domain_result = lookup_indicator(
        hostname,
        force=force,
    )

    return {
        "url": normalized_url,
        "hostname": hostname,
        "url_result": url_result,
        "domain_result": domain_result,
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
            FROM virustotal_observations
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
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(
                    CASE
                        WHEN lookup_status = 'success'
                        THEN 1 ELSE 0
                    END
                ) AS successful,
                SUM(
                    CASE
                        WHEN lookup_status = 'failed'
                        THEN 1 ELSE 0
                    END
                ) AS failed,
                SUM(
                    CASE
                        WHEN malicious > 0
                        OR suspicious > 0
                        THEN 1 ELSE 0
                    END
                ) AS detected
            FROM virustotal_observations
            """
        ).fetchone()

    return {
        "observed_indicators": int(
            row[
                "total"
            ]
            or 0
        ),
        "successful_lookups": int(
            row[
                "successful"
            ]
            or 0
        ),
        "failed_lookups": int(
            row[
                "failed"
            ]
            or 0
        ),
        "detected_indicators": int(
            row[
                "detected"
            ]
            or 0
        ),
        "cache_hours": CACHE_HOURS,
        "minimum_request_interval_seconds": (
            MINIMUM_REQUEST_INTERVAL
        ),
    }
