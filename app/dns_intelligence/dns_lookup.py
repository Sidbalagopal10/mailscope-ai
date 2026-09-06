from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import tldextract


DATABASE_PATH = Path(
    "data/dns_intelligence/dns_intelligence.db"
)

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 10.0

QUERY_TYPES = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CAA",
    "SOA",
    "CNAME",
    "DS",
)


class DNSIntelligenceError(Exception):
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
        raise DNSIntelligenceError(
            "A domain is required."
        )

    if "://" in cleaned:
        parsed = urlparse(
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
        raise DNSIntelligenceError(
            "Enter a complete domain such as example.org."
        )

    try:
        ipaddress.ip_address(
            cleaned
        )

    except ValueError:
        pass

    else:
        raise DNSIntelligenceError(
            "DNS domain analysis does not accept IP addresses."
        )

    try:
        return cleaned.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise DNSIntelligenceError(
            "The domain could not be converted to IDNA."
        ) from error


def registrable_domain(
    value: str,
) -> str:
    normalized = normalize_domain(
        value
    )

    extracted = tldextract.extract(
        normalized
    )

    registered = (
        extracted.top_domain_under_public_suffix
    )

    return (
        registered
        or normalized
    )


def create_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(
        configure=True
    )

    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_LIFETIME

    return resolver


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
            CREATE TABLE IF NOT EXISTS dns_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                registrable_domain TEXT NOT NULL,
                lookup_status TEXT NOT NULL,

                a_json TEXT NOT NULL,
                aaaa_json TEXT NOT NULL,
                mx_json TEXT NOT NULL,
                ns_json TEXT NOT NULL,
                txt_json TEXT NOT NULL,
                caa_json TEXT NOT NULL,
                soa_json TEXT NOT NULL,
                cname_json TEXT NOT NULL,
                ds_json TEXT NOT NULL,

                spf_records_json TEXT NOT NULL,
                dmarc_records_json TEXT NOT NULL,

                has_a INTEGER NOT NULL DEFAULT 0,
                has_aaaa INTEGER NOT NULL DEFAULT 0,
                has_mx INTEGER NOT NULL DEFAULT 0,
                has_spf INTEGER NOT NULL DEFAULT 0,
                has_dmarc INTEGER NOT NULL DEFAULT 0,
                has_caa INTEGER NOT NULL DEFAULT 0,
                has_dnssec_delegation INTEGER NOT NULL DEFAULT 0,

                mx_count INTEGER NOT NULL DEFAULT 0,
                ns_count INTEGER NOT NULL DEFAULT 0,
                txt_count INTEGER NOT NULL DEFAULT 0,

                minimum_ttl INTEGER,
                maximum_ttl INTEGER,

                errors_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_dns_lookup_status
            ON dns_observations(lookup_status);

            CREATE INDEX IF NOT EXISTS
            idx_dns_has_mx
            ON dns_observations(has_mx);

            CREATE INDEX IF NOT EXISTS
            idx_dns_has_dmarc
            ON dns_observations(has_dmarc);

            CREATE INDEX IF NOT EXISTS
            idx_dns_registrable_domain
            ON dns_observations(registrable_domain);
            """
        )

        connection.commit()


def text_from_txt_record(
    record: Any,
) -> str:
    strings = getattr(
        record,
        "strings",
        None,
    )

    if strings is not None:
        return "".join(
            (
                value.decode(
                    "utf-8",
                    errors="replace",
                )
                if isinstance(
                    value,
                    bytes,
                )
                else str(value)
            )
            for value in strings
        )

    rendered = record.to_text()

    if (
        rendered.startswith('"')
        and rendered.endswith('"')
    ):
        rendered = rendered[1:-1]

    return rendered.replace(
        '" "',
        "",
    )


def serialize_record(
    record_type: str,
    record: Any,
) -> dict[str, Any]:
    record_type = record_type.upper()

    if record_type == "A":
        return {
            "address": str(
                record.address
            )
        }

    if record_type == "AAAA":
        return {
            "address": str(
                record.address
            )
        }

    if record_type == "MX":
        return {
            "preference": int(
                record.preference
            ),
            "exchange": str(
                record.exchange
            ).lower().rstrip("."),
        }

    if record_type == "NS":
        return {
            "target": str(
                record.target
            ).lower().rstrip("."),
        }

    if record_type == "TXT":
        return {
            "text": text_from_txt_record(
                record
            )
        }

    if record_type == "CAA":
        value = record.value

        if isinstance(
            value,
            bytes,
        ):
            value = value.decode(
                "utf-8",
                errors="replace",
            )

        return {
            "flags": int(
                record.flags
            ),
            "tag": str(
                record.tag.decode(
                    "utf-8",
                    errors="replace",
                )
                if isinstance(
                    record.tag,
                    bytes,
                )
                else record.tag
            ),
            "value": str(
                value
            ),
        }

    if record_type == "SOA":
        return {
            "mname": str(
                record.mname
            ).lower().rstrip("."),
            "rname": str(
                record.rname
            ).lower().rstrip("."),
            "serial": int(
                record.serial
            ),
            "refresh": int(
                record.refresh
            ),
            "retry": int(
                record.retry
            ),
            "expire": int(
                record.expire
            ),
            "minimum": int(
                record.minimum
            ),
        }

    if record_type == "CNAME":
        return {
            "target": str(
                record.target
            ).lower().rstrip("."),
        }

    if record_type == "DS":
        return {
            "key_tag": int(
                record.key_tag
            ),
            "algorithm": int(
                record.algorithm
            ),
            "digest_type": int(
                record.digest_type
            ),
            "digest": str(
                record.digest
            ),
        }

    return {
        "text": record.to_text()
    }


def query_record(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> dict[str, Any]:
    try:
        answer = resolver.resolve(
            name,
            record_type,
            raise_on_no_answer=False,
            search=False,
        )

        records = []

        if answer.rrset is not None:
            records = [
                serialize_record(
                    record_type,
                    record,
                )
                for record in answer
            ]

            ttl = int(
                answer.rrset.ttl
            )

        else:
            ttl = None

        return {
            "status": (
                "success"
                if records
                else "no_answer"
            ),
            "records": records,
            "ttl": ttl,
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "nxdomain",
            "records": [],
            "ttl": None,
            "error": "Domain does not exist.",
        }

    except dns.resolver.NoNameservers as error:
        return {
            "status": "no_nameservers",
            "records": [],
            "ttl": None,
            "error": str(
                error
            ),
        }

    except dns.resolver.LifetimeTimeout:
        return {
            "status": "timeout",
            "records": [],
            "ttl": None,
            "error": "DNS query timed out.",
        }

    except dns.resolver.NoAnswer:
        return {
            "status": "no_answer",
            "records": [],
            "ttl": None,
            "error": None,
        }

    except dns.exception.DNSException as error:
        return {
            "status": "failed",
            "records": [],
            "ttl": None,
            "error": str(
                error
            ),
        }


def extract_spf_records(
    txt_records: list[dict[str, Any]],
) -> list[str]:
    return sorted(
        {
            str(
                item.get(
                    "text",
                    "",
                )
            ).strip()
            for item in txt_records
            if str(
                item.get(
                    "text",
                    "",
                )
            ).strip().lower().startswith(
                "v=spf1"
            )
        }
    )


def extract_dmarc_records(
    txt_records: list[dict[str, Any]],
) -> list[str]:
    return sorted(
        {
            str(
                item.get(
                    "text",
                    "",
                )
            ).strip()
            for item in txt_records
            if str(
                item.get(
                    "text",
                    "",
                )
            ).strip().lower().startswith(
                "v=dmarc1"
            )
        }
    )


def analyze_domain(
    domain: str,
) -> dict[str, Any]:
    normalized = normalize_domain(
        domain
    )

    base_domain = registrable_domain(
        normalized
    )

    resolver = create_resolver()

    query_results: dict[
        str,
        dict[str, Any],
    ] = {}

    errors = []

    for record_type in QUERY_TYPES:
        result = query_record(
            resolver,
            normalized,
            record_type,
        )

        query_results[
            record_type
        ] = result

        if result.get(
            "error"
        ):
            errors.append(
                {
                    "name": normalized,
                    "record_type": record_type,
                    "error": result[
                        "error"
                    ],
                }
            )

    dmarc_name = (
        f"_dmarc.{base_domain}"
    )

    dmarc_result = query_record(
        resolver,
        dmarc_name,
        "TXT",
    )

    if dmarc_result.get(
        "error"
    ):
        errors.append(
            {
                "name": dmarc_name,
                "record_type": "TXT",
                "error": dmarc_result[
                    "error"
                ],
            }
        )

    txt_records = query_results[
        "TXT"
    ][
        "records"
    ]

    spf_records = extract_spf_records(
        txt_records
    )

    dmarc_records = extract_dmarc_records(
        dmarc_result[
            "records"
        ]
    )

    ttl_values = [
        int(
            result["ttl"]
        )
        for result in [
            *query_results.values(),
            dmarc_result,
        ]
        if result.get(
            "ttl"
        )
        is not None
    ]

    a_records = query_results[
        "A"
    ][
        "records"
    ]

    aaaa_records = query_results[
        "AAAA"
    ][
        "records"
    ]

    mx_records = query_results[
        "MX"
    ][
        "records"
    ]

    ns_records = query_results[
        "NS"
    ][
        "records"
    ]

    caa_records = query_results[
        "CAA"
    ][
        "records"
    ]

    ds_records = query_results[
        "DS"
    ][
        "records"
    ]

    lookup_status = (
        "success"
        if any(
            [
                a_records,
                aaaa_records,
                mx_records,
                ns_records,
                query_results[
                    "SOA"
                ][
                    "records"
                ],
            ]
        )
        else "limited"
    )

    return {
        "domain": normalized,
        "registrable_domain": (
            base_domain
        ),
        "lookup_status": lookup_status,
        "records": {
            record_type.lower(): (
                query_results[
                    record_type
                ][
                    "records"
                ]
            )
            for record_type in QUERY_TYPES
        },
        "spf_records": spf_records,
        "dmarc_records": dmarc_records,
        "dmarc_lookup_name": (
            dmarc_name
        ),
        "has_a": bool(
            a_records
        ),
        "has_aaaa": bool(
            aaaa_records
        ),
        "has_mx": bool(
            mx_records
        ),
        "has_spf": bool(
            spf_records
        ),
        "has_dmarc": bool(
            dmarc_records
        ),
        "has_caa": bool(
            caa_records
        ),
        "has_dnssec_delegation": bool(
            ds_records
        ),
        "mx_count": len(
            mx_records
        ),
        "ns_count": len(
            ns_records
        ),
        "txt_count": len(
            txt_records
        ),
        "minimum_ttl": (
            min(
                ttl_values
            )
            if ttl_values
            else None
        ),
        "maximum_ttl": (
            max(
                ttl_values
            )
            if ttl_values
            else None
        ),
        "query_status": {
            record_type.lower(): {
                "status": query_results[
                    record_type
                ][
                    "status"
                ],
                "ttl": query_results[
                    record_type
                ][
                    "ttl"
                ],
            }
            for record_type in QUERY_TYPES
        },
        "errors": errors,
        "observed_at": utc_now(),
    }


def save_observation(
    observation: dict[str, Any],
) -> dict[str, Any]:
    initialize_database()

    timestamp = utc_now()

    records = observation.get(
        "records",
        {},
    )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO dns_observations (
                domain,
                registrable_domain,
                lookup_status,

                a_json,
                aaaa_json,
                mx_json,
                ns_json,
                txt_json,
                caa_json,
                soa_json,
                cname_json,
                ds_json,

                spf_records_json,
                dmarc_records_json,

                has_a,
                has_aaaa,
                has_mx,
                has_spf,
                has_dmarc,
                has_caa,
                has_dnssec_delegation,

                mx_count,
                ns_count,
                txt_count,

                minimum_ttl,
                maximum_ttl,

                errors_json,
                observed_at,
                updated_at
            )
            VALUES (
                ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?
            )
            ON CONFLICT(domain)
            DO UPDATE SET
                registrable_domain = excluded.registrable_domain,
                lookup_status = excluded.lookup_status,

                a_json = excluded.a_json,
                aaaa_json = excluded.aaaa_json,
                mx_json = excluded.mx_json,
                ns_json = excluded.ns_json,
                txt_json = excluded.txt_json,
                caa_json = excluded.caa_json,
                soa_json = excluded.soa_json,
                cname_json = excluded.cname_json,
                ds_json = excluded.ds_json,

                spf_records_json = excluded.spf_records_json,
                dmarc_records_json = excluded.dmarc_records_json,

                has_a = excluded.has_a,
                has_aaaa = excluded.has_aaaa,
                has_mx = excluded.has_mx,
                has_spf = excluded.has_spf,
                has_dmarc = excluded.has_dmarc,
                has_caa = excluded.has_caa,
                has_dnssec_delegation =
                    excluded.has_dnssec_delegation,

                mx_count = excluded.mx_count,
                ns_count = excluded.ns_count,
                txt_count = excluded.txt_count,

                minimum_ttl = excluded.minimum_ttl,
                maximum_ttl = excluded.maximum_ttl,

                errors_json = excluded.errors_json,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at
            """,
            (
                observation[
                    "domain"
                ],
                observation[
                    "registrable_domain"
                ],
                observation[
                    "lookup_status"
                ],

                json.dumps(
                    records.get(
                        "a",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "aaaa",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "mx",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "ns",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "txt",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "caa",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "soa",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "cname",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    records.get(
                        "ds",
                        [],
                    ),
                    sort_keys=True,
                ),

                json.dumps(
                    observation.get(
                        "spf_records",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "dmarc_records",
                        [],
                    ),
                    sort_keys=True,
                ),

                int(
                    observation.get(
                        "has_a",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_aaaa",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_mx",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_spf",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_dmarc",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_caa",
                        False,
                    )
                ),
                int(
                    observation.get(
                        "has_dnssec_delegation",
                        False,
                    )
                ),

                int(
                    observation.get(
                        "mx_count",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "ns_count",
                        0,
                    )
                ),
                int(
                    observation.get(
                        "txt_count",
                        0,
                    )
                ),

                observation.get(
                    "minimum_ttl"
                ),
                observation.get(
                    "maximum_ttl"
                ),

                json.dumps(
                    observation.get(
                        "errors",
                        [],
                    ),
                    sort_keys=True,
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
            "domain"
        ]
    )

    if saved is None:
        raise DNSIntelligenceError(
            "DNS observation could not be saved."
        )

    return saved


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    mappings = {
        "a_json": "a",
        "aaaa_json": "aaaa",
        "mx_json": "mx",
        "ns_json": "ns",
        "txt_json": "txt",
        "caa_json": "caa",
        "soa_json": "soa",
        "cname_json": "cname",
        "ds_json": "ds",
        "spf_records_json": (
            "spf_records"
        ),
        "dmarc_records_json": (
            "dmarc_records"
        ),
        "errors_json": "errors",
    }

    for source, destination in mappings.items():
        raw_value = result.pop(
            source,
            None,
        )

        try:
            result[
                destination
            ] = (
                json.loads(
                    raw_value
                )
                if raw_value
                else []
            )

        except json.JSONDecodeError:
            result[
                destination
            ] = []

    for boolean_field in (
        "has_a",
        "has_aaaa",
        "has_mx",
        "has_spf",
        "has_dmarc",
        "has_caa",
        "has_dnssec_delegation",
    ):
        result[
            boolean_field
        ] = bool(
            result.get(
                boolean_field
            )
        )

    result["records"] = {
        record_type: result.get(
            record_type,
            [],
        )
        for record_type in (
            "a",
            "aaaa",
            "mx",
            "ns",
            "txt",
            "caa",
            "soa",
            "cname",
            "ds",
        )
    }

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
            FROM dns_observations
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

    observation = analyze_domain(
        normalized
    )

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
            FROM dns_observations
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
            FROM dns_observations
            """
        ).fetchone()["count"]

        successful = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dns_observations
            WHERE lookup_status = 'success'
            """
        ).fetchone()["count"]

        email_capable = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dns_observations
            WHERE has_mx = 1
            """
        ).fetchone()["count"]

        with_spf = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dns_observations
            WHERE has_spf = 1
            """
        ).fetchone()["count"]

        with_dmarc = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dns_observations
            WHERE has_dmarc = 1
            """
        ).fetchone()["count"]

        with_dnssec = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dns_observations
            WHERE has_dnssec_delegation = 1
            """
        ).fetchone()["count"]

    return {
        "observed_domains": int(
            total
        ),
        "successful_lookups": int(
            successful
        ),
        "limited_or_failed": int(
            total - successful
        ),
        "domains_with_mx": int(
            email_capable
        ),
        "domains_with_spf": int(
            with_spf
        ),
        "domains_with_dmarc": int(
            with_dmarc
        ),
        "domains_with_dnssec_delegation": int(
            with_dnssec
        ),
    }
