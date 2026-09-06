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


DATABASE_PATH = Path(
    "data/domain_intelligence/"
    "certificate_transparency.db"
)

CRT_SH_URL = "https://crt.sh/"

USER_AGENT = (
    "AI-Email-Security-Platform/1.0 "
    "(local research and defensive security project)"
)

DEFAULT_TIMEOUT = 40


class CertificateTransparencyError(
    Exception
):
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
        raise CertificateTransparencyError(
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

    if cleaned.startswith(
        "www."
    ):
        cleaned = cleaned[4:]

    if (
        not cleaned
        or "." not in cleaned
        or " " in cleaned
        or "@" in cleaned
    ):
        raise CertificateTransparencyError(
            "Enter a complete domain such as example.org."
        )

    try:
        ipaddress.ip_address(
            cleaned
        )

    except ValueError:
        pass

    else:
        raise CertificateTransparencyError(
            "Certificate-domain lookup does not "
            "accept IP addresses."
        )

    try:
        return cleaned.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise CertificateTransparencyError(
            "The domain could not be converted to IDNA."
        ) from error


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
        formats = (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        )

        for date_format in formats:
            try:
                parsed = datetime.strptime(
                    text,
                    date_format,
                )

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

                break

            except ValueError:
                continue

        else:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


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
            CREATE TABLE IF NOT EXISTS ct_domain_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                lookup_status TEXT NOT NULL,
                certificate_count INTEGER NOT NULL DEFAULT 0,
                unique_name_count INTEGER NOT NULL DEFAULT 0,
                wildcard_name_count INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                newest_not_before TEXT,
                newest_not_after TEXT,
                newest_issuer_name TEXT,
                newest_common_name TEXT,
                error_message TEXT,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ct_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queried_domain TEXT NOT NULL,
                certificate_id TEXT,
                common_name TEXT,
                name_value TEXT,
                issuer_name TEXT,
                issuer_ca_id TEXT,
                entry_timestamp TEXT,
                not_before TEXT,
                not_after TEXT,
                serial_number TEXT,
                result_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                UNIQUE (
                    queried_domain,
                    certificate_id,
                    serial_number
                )
            );

            CREATE INDEX IF NOT EXISTS
            idx_ct_summary_domain
            ON ct_domain_summaries(domain);

            CREATE INDEX IF NOT EXISTS
            idx_ct_certificate_domain
            ON ct_certificates(queried_domain);

            CREATE INDEX IF NOT EXISTS
            idx_ct_certificate_timestamp
            ON ct_certificates(entry_timestamp);
            """
        )

        connection.commit()


def request_json(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
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
        raise CertificateTransparencyError(
            "Certificate Transparency index returned "
            f"HTTP {error.code}."
        ) from error

    except urllib.error.URLError as error:
        raise CertificateTransparencyError(
            "Unable to contact the Certificate "
            f"Transparency index: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise CertificateTransparencyError(
            "Certificate Transparency lookup timed out."
        ) from error

    except json.JSONDecodeError as error:
        raise CertificateTransparencyError(
            "Certificate Transparency index "
            "returned invalid JSON."
        ) from error

    if not isinstance(
        payload,
        list,
    ):
        raise CertificateTransparencyError(
            "Certificate Transparency index returned "
            "an unsupported response."
        )

    return [
        item
        for item in payload
        if isinstance(
            item,
            dict,
        )
    ]


def build_query_url(
    domain: str,
    *,
    include_subdomains: bool = True,
) -> str:
    normalized = normalize_domain(
        domain
    )

    query = (
        f"%.{normalized}"
        if include_subdomains
        else normalized
    )

    parameters = urllib.parse.urlencode(
        {
            "q": query,
            "output": "json",
        }
    )

    return (
        f"{CRT_SH_URL}?"
        f"{parameters}"
    )


def extract_names(
    result: dict[str, Any],
) -> set[str]:
    values = set()

    for field in (
        "common_name",
        "name_value",
    ):
        raw_value = str(
            result.get(
                field,
                "",
            )
            or ""
        )

        for value in raw_value.splitlines():
            cleaned = (
                value.strip()
                .lower()
                .rstrip(".")
            )

            if cleaned:
                values.add(
                    cleaned
                )

    return values


def name_matches_domain(
    name: str,
    domain: str,
) -> bool:
    cleaned = str(
        name or ""
    ).strip().lower()

    if cleaned.startswith(
        "*."
    ):
        cleaned = cleaned[2:]

    return (
        cleaned == domain
        or cleaned.endswith(
            f".{domain}"
        )
    )


def deduplicate_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    selected: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    for result in results:
        key = (
            str(
                result.get(
                    "id",
                    "",
                )
            ),
            str(
                result.get(
                    "serial_number",
                    "",
                )
            ),
            str(
                result.get(
                    "entry_timestamp",
                    "",
                )
            ),
        )

        selected[
            key
        ] = result

    return list(
        selected.values()
    )


def summarize_results(
    *,
    domain: str,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = normalize_domain(
        domain
    )

    filtered_results = []

    all_names: set[str] = set()
    wildcard_names: set[str] = set()
    timestamps: list[datetime] = []
    not_before_dates: list[datetime] = []
    not_after_dates: list[datetime] = []

    for result in deduplicate_results(
        results
    ):
        names = extract_names(
            result
        )

        matching_names = {
            name
            for name in names
            if name_matches_domain(
                name,
                normalized,
            )
        }

        if not matching_names:
            continue

        all_names.update(
            matching_names
        )

        wildcard_names.update(
            {
                name
                for name in matching_names
                if name.startswith(
                    "*."
                )
            }
        )

        timestamp = parse_datetime(
            result.get(
                "entry_timestamp"
            )
        )

        not_before = parse_datetime(
            result.get(
                "not_before"
            )
        )

        not_after = parse_datetime(
            result.get(
                "not_after"
            )
        )

        if timestamp:
            timestamps.append(
                timestamp
            )

        if not_before:
            not_before_dates.append(
                not_before
            )

        if not_after:
            not_after_dates.append(
                not_after
            )

        filtered_results.append(
            result
        )

    newest_result = None

    if filtered_results:
        newest_result = max(
            filtered_results,
            key=lambda item: (
                parse_datetime(
                    item.get(
                        "entry_timestamp"
                    )
                )
                or datetime.min.replace(
                    tzinfo=timezone.utc
                )
            ),
        )

    return {
        "domain": normalized,
        "lookup_status": "success",
        "certificate_count": len(
            filtered_results
        ),
        "unique_name_count": len(
            all_names
        ),
        "wildcard_name_count": len(
            wildcard_names
        ),
        "names": sorted(
            all_names
        ),
        "first_seen": (
            min(
                timestamps
            ).isoformat()
            if timestamps
            else None
        ),
        "last_seen": (
            max(
                timestamps
            ).isoformat()
            if timestamps
            else None
        ),
        "newest_not_before": (
            max(
                not_before_dates
            ).isoformat()
            if not_before_dates
            else None
        ),
        "newest_not_after": (
            max(
                not_after_dates
            ).isoformat()
            if not_after_dates
            else None
        ),
        "newest_issuer_name": (
            newest_result.get(
                "issuer_name"
            )
            if newest_result
            else None
        ),
        "newest_common_name": (
            newest_result.get(
                "common_name"
            )
            if newest_result
            else None
        ),
        "results": filtered_results,
        "error_message": None,
        "observed_at": utc_now(),
    }


def save_lookup(
    summary: dict[str, Any],
) -> dict[str, Any]:
    initialize_database()

    timestamp = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO ct_domain_summaries (
                domain,
                lookup_status,
                certificate_count,
                unique_name_count,
                wildcard_name_count,
                first_seen,
                last_seen,
                newest_not_before,
                newest_not_after,
                newest_issuer_name,
                newest_common_name,
                error_message,
                observed_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(domain)
            DO UPDATE SET
                lookup_status = excluded.lookup_status,
                certificate_count = excluded.certificate_count,
                unique_name_count = excluded.unique_name_count,
                wildcard_name_count = excluded.wildcard_name_count,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                newest_not_before = excluded.newest_not_before,
                newest_not_after = excluded.newest_not_after,
                newest_issuer_name = excluded.newest_issuer_name,
                newest_common_name = excluded.newest_common_name,
                error_message = excluded.error_message,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at
            """,
            (
                summary["domain"],
                summary[
                    "lookup_status"
                ],
                int(
                    summary.get(
                        "certificate_count",
                        0,
                    )
                ),
                int(
                    summary.get(
                        "unique_name_count",
                        0,
                    )
                ),
                int(
                    summary.get(
                        "wildcard_name_count",
                        0,
                    )
                ),
                summary.get(
                    "first_seen"
                ),
                summary.get(
                    "last_seen"
                ),
                summary.get(
                    "newest_not_before"
                ),
                summary.get(
                    "newest_not_after"
                ),
                summary.get(
                    "newest_issuer_name"
                ),
                summary.get(
                    "newest_common_name"
                ),
                summary.get(
                    "error_message"
                ),
                summary.get(
                    "observed_at",
                    timestamp,
                ),
                timestamp,
            ),
        )

        for result in summary.get(
            "results",
            [],
        ):
            connection.execute(
                """
                INSERT OR IGNORE INTO ct_certificates (
                    queried_domain,
                    certificate_id,
                    common_name,
                    name_value,
                    issuer_name,
                    issuer_ca_id,
                    entry_timestamp,
                    not_before,
                    not_after,
                    serial_number,
                    result_json,
                    observed_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    summary[
                        "domain"
                    ],
                    str(
                        result.get(
                            "id",
                            "",
                        )
                    ),
                    result.get(
                        "common_name"
                    ),
                    result.get(
                        "name_value"
                    ),
                    result.get(
                        "issuer_name"
                    ),
                    str(
                        result.get(
                            "issuer_ca_id",
                            "",
                        )
                    ),
                    result.get(
                        "entry_timestamp"
                    ),
                    result.get(
                        "not_before"
                    ),
                    result.get(
                        "not_after"
                    ),
                    result.get(
                        "serial_number"
                    ),
                    json.dumps(
                        result,
                        sort_keys=True,
                    ),
                    timestamp,
                ),
            )

        connection.commit()

    saved = get_summary_for_domain(
        summary["domain"]
    )

    if saved is None:
        raise CertificateTransparencyError(
            "Certificate Transparency result "
            "could not be saved."
        )

    saved["names"] = summary.get(
        "names",
        [],
    )

    return saved


def get_summary_for_domain(
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
            FROM ct_domain_summaries
            WHERE domain = ?
            """,
            (
                normalized,
            ),
        ).fetchone()

    return (
        dict(
            row
        )
        if row is not None
        else None
    )


def lookup_domain(
    domain: str,
    *,
    include_subdomains: bool = True,
    force: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    normalized = normalize_domain(
        domain
    )

    if not force:
        cached = get_summary_for_domain(
            normalized
        )

        if cached is not None:
            return {
                **cached,
                "cache_status": "cached",
            }

    try:
        results = request_json(
            build_query_url(
                normalized,
                include_subdomains=(
                    include_subdomains
                ),
            ),
            timeout=timeout,
        )

        summary = summarize_results(
            domain=normalized,
            results=results,
        )

    except Exception as error:
        summary = {
            "domain": normalized,
            "lookup_status": "failed",
            "certificate_count": 0,
            "unique_name_count": 0,
            "wildcard_name_count": 0,
            "names": [],
            "first_seen": None,
            "last_seen": None,
            "newest_not_before": None,
            "newest_not_after": None,
            "newest_issuer_name": None,
            "newest_common_name": None,
            "results": [],
            "error_message": str(
                error
            ),
            "observed_at": utc_now(),
        }

    saved = save_lookup(
        summary
    )

    return {
        **saved,
        "names": summary.get(
            "names",
            [],
        ),
        "cache_status": "fresh",
    }


def list_summaries(
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
            FROM ct_domain_summaries
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (
                safe_limit,
            ),
        ).fetchall()

    return [
        dict(
            row
        )
        for row in rows
    ]


def get_global_summary() -> dict[str, Any]:
    initialize_database()

    with get_connection() as connection:
        total = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM ct_domain_summaries
            """
        ).fetchone()["count"]

        successful = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM ct_domain_summaries
            WHERE lookup_status = 'success'
            """
        ).fetchone()["count"]

        certificates = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM ct_certificates
            """
        ).fetchone()["count"]

        names = connection.execute(
            """
            SELECT COALESCE(
                SUM(unique_name_count),
                0
            ) AS count
            FROM ct_domain_summaries
            """
        ).fetchone()["count"]

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
        "stored_certificates": int(
            certificates
        ),
        "unique_certificate_names": int(
            names
        ),
    }
