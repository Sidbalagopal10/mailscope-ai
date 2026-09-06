from __future__ import annotations

import ipaddress
import json
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.reversename
import dns.resolver


DATABASE_PATH = Path(
    "data/network_intelligence/ip_asn_intelligence.db"
)

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 10.0

CYMRU_V4_SUFFIX = "origin.asn.cymru.com"
CYMRU_V6_SUFFIX = "origin6.asn.cymru.com"
CYMRU_ASN_SUFFIX = "asn.cymru.com"


class IPASNIntelligenceError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_hostname(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip().lower()

    if not cleaned:
        raise IPASNIntelligenceError(
            "A domain or hostname is required."
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

    if cleaned.startswith("www."):
        cleaned = cleaned[4:]

    if (
        not cleaned
        or "." not in cleaned
        or " " in cleaned
        or "@" in cleaned
    ):
        raise IPASNIntelligenceError(
            "Enter a complete hostname such as example.org."
        )

    try:
        return cleaned.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError as error:
        raise IPASNIntelligenceError(
            "The hostname could not be converted to IDNA."
        ) from error


def normalize_ip(
    value: str,
) -> str:
    try:
        return str(
            ipaddress.ip_address(
                str(
                    value
                ).strip()
            )
        )

    except ValueError as error:
        raise IPASNIntelligenceError(
            f"Invalid IP address: {value}"
        ) from error


def is_public_ip(
    value: str,
) -> bool:
    address = ipaddress.ip_address(
        normalize_ip(
            value
        )
    )

    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
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
            CREATE TABLE IF NOT EXISTS network_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL UNIQUE,
                lookup_status TEXT NOT NULL,
                ipv4_addresses_json TEXT NOT NULL,
                ipv6_addresses_json TEXT NOT NULL,
                public_addresses_json TEXT NOT NULL,
                private_or_special_addresses_json TEXT NOT NULL,
                asn_records_json TEXT NOT NULL,
                unique_asns_json TEXT NOT NULL,
                unique_network_names_json TEXT NOT NULL,
                reverse_dns_json TEXT NOT NULL,
                error_messages_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_network_lookup_status
            ON network_observations(lookup_status);

            CREATE INDEX IF NOT EXISTS
            idx_network_hostname
            ON network_observations(hostname);
            """
        )

        connection.commit()


def txt_value(
    record: Any,
) -> str:
    strings = getattr(
        record,
        "strings",
        None,
    )

    if strings:
        return "".join(
            value.decode(
                "utf-8",
                errors="replace",
            )
            if isinstance(
                value,
                bytes,
            )
            else str(
                value
            )
            for value in strings
        )

    return (
        record.to_text()
        .strip('"')
        .replace(
            '" "',
            "",
        )
    )


def resolve_addresses(
    hostname: str,
) -> dict[str, Any]:
    normalized = normalize_hostname(
        hostname
    )

    resolver = create_resolver()

    result: dict[str, Any] = {
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "errors": [],
    }

    for record_type, destination in (
        (
            "A",
            "ipv4_addresses",
        ),
        (
            "AAAA",
            "ipv6_addresses",
        ),
    ):
        try:
            answer = resolver.resolve(
                normalized,
                record_type,
                raise_on_no_answer=False,
                search=False,
            )

            if answer.rrset is not None:
                result[
                    destination
                ] = sorted(
                    {
                        str(
                            record.address
                        )
                        for record in answer
                    }
                )

        except dns.resolver.NXDOMAIN:
            result[
                "errors"
            ].append(
                {
                    "record_type": record_type,
                    "error": "Hostname does not exist.",
                }
            )

        except (
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.DNSException,
        ) as error:
            result[
                "errors"
            ].append(
                {
                    "record_type": record_type,
                    "error": str(
                        error
                    ),
                }
            )

    return result


def cymru_origin_query_name(
    ip_address: str,
) -> str:
    address = ipaddress.ip_address(
        normalize_ip(
            ip_address
        )
    )

    if address.version == 4:
        reversed_octets = ".".join(
            reversed(
                str(
                    address
                ).split(".")
            )
        )

        return (
            f"{reversed_octets}."
            f"{CYMRU_V4_SUFFIX}"
        )

    hexadecimal = address.exploded.replace(
        ":",
        "",
    )

    reversed_nibbles = ".".join(
        reversed(
            hexadecimal
        )
    )

    return (
        f"{reversed_nibbles}."
        f"{CYMRU_V6_SUFFIX}"
    )


def parse_origin_response(
    value: str,
) -> dict[str, Any]:
    parts = [
        part.strip()
        for part in str(
            value
        ).split("|")
    ]

    while len(parts) < 5:
        parts.append("")

    asn_value = parts[0].replace(
        "AS",
        "",
    ).strip()

    asns = []

    for token in asn_value.replace(
        ",",
        " ",
    ).split():
        if token.isdigit():
            asns.append(
                int(
                    token
                )
            )

    return {
        "asns": sorted(
            set(
                asns
            )
        ),
        "prefix": parts[1] or None,
        "country_code": (
            parts[2].upper()
            if parts[2]
            else None
        ),
        "registry": (
            parts[3].lower()
            if parts[3]
            else None
        ),
        "allocated_date": (
            parts[4]
            or None
        ),
    }


def lookup_origin(
    ip_address: str,
) -> dict[str, Any]:
    normalized_ip = normalize_ip(
        ip_address
    )

    if not is_public_ip(
        normalized_ip
    ):
        return {
            "ip_address": normalized_ip,
            "available": False,
            "error": (
                "The address is private, reserved or "
                "otherwise non-global."
            ),
            "asns": [],
            "prefix": None,
            "country_code": None,
            "registry": None,
            "allocated_date": None,
        }

    resolver = create_resolver()

    query_name = cymru_origin_query_name(
        normalized_ip
    )

    try:
        answer = resolver.resolve(
            query_name,
            "TXT",
            search=False,
        )

        if not answer:
            raise IPASNIntelligenceError(
                "No ASN mapping response was returned."
            )

        parsed = parse_origin_response(
            txt_value(
                answer[0]
            )
        )

        return {
            "ip_address": normalized_ip,
            "available": True,
            "error": None,
            **parsed,
        }

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ) as error:
        return {
            "ip_address": normalized_ip,
            "available": False,
            "error": str(
                error
            ),
            "asns": [],
            "prefix": None,
            "country_code": None,
            "registry": None,
            "allocated_date": None,
        }


def parse_asn_response(
    value: str,
) -> dict[str, Any]:
    parts = [
        part.strip()
        for part in str(
            value
        ).split("|")
    ]

    while len(parts) < 5:
        parts.append("")

    return {
        "asn": (
            int(
                parts[0].replace(
                    "AS",
                    "",
                )
            )
            if parts[0].replace(
                "AS",
                "",
            ).isdigit()
            else None
        ),
        "country_code": (
            parts[1].upper()
            if parts[1]
            else None
        ),
        "registry": (
            parts[2].lower()
            if parts[2]
            else None
        ),
        "allocated_date": (
            parts[3]
            or None
        ),
        "network_name": (
            parts[4]
            or None
        ),
    }


def lookup_asn(
    asn: int,
) -> dict[str, Any]:
    normalized_asn = int(
        asn
    )

    if normalized_asn <= 0:
        raise IPASNIntelligenceError(
            "ASN must be a positive integer."
        )

    resolver = create_resolver()

    query_name = (
        f"AS{normalized_asn}."
        f"{CYMRU_ASN_SUFFIX}"
    )

    try:
        answer = resolver.resolve(
            query_name,
            "TXT",
            search=False,
        )

        if not answer:
            raise IPASNIntelligenceError(
                "No ASN identity response was returned."
            )

        parsed = parse_asn_response(
            txt_value(
                answer[0]
            )
        )

        return {
            "available": True,
            "error": None,
            **parsed,
        }

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ) as error:
        return {
            "available": False,
            "error": str(
                error
            ),
            "asn": normalized_asn,
            "country_code": None,
            "registry": None,
            "allocated_date": None,
            "network_name": None,
        }


def reverse_dns_lookup(
    ip_address: str,
) -> dict[str, Any]:
    normalized_ip = normalize_ip(
        ip_address
    )

    if not is_public_ip(
        normalized_ip
    ):
        return {
            "ip_address": normalized_ip,
            "names": [],
            "error": (
                "Reverse DNS was skipped for a "
                "non-global address."
            ),
        }

    resolver = create_resolver()

    try:
        reverse_name = dns.reversename.from_address(
            normalized_ip
        )

        answer = resolver.resolve(
            reverse_name,
            "PTR",
            raise_on_no_answer=False,
            search=False,
        )

        names = []

        if answer.rrset is not None:
            names = sorted(
                {
                    str(
                        record.target
                    ).lower().rstrip(".")
                    for record in answer
                }
            )

        return {
            "ip_address": normalized_ip,
            "names": names,
            "error": None,
        }

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ) as error:
        return {
            "ip_address": normalized_ip,
            "names": [],
            "error": str(
                error
            ),
        }


def analyze_hostname(
    hostname: str,
) -> dict[str, Any]:
    normalized = normalize_hostname(
        hostname
    )

    address_result = resolve_addresses(
        normalized
    )

    all_addresses = sorted(
        set(
            address_result[
                "ipv4_addresses"
            ]
            + address_result[
                "ipv6_addresses"
            ]
        )
    )

    public_addresses = [
        address
        for address in all_addresses
        if is_public_ip(
            address
        )
    ]

    private_or_special = [
        address
        for address in all_addresses
        if not is_public_ip(
            address
        )
    ]

    asn_records = []
    reverse_dns = []
    errors = list(
        address_result[
            "errors"
        ]
    )

    for address in public_addresses:
        origin = lookup_origin(
            address
        )

        if origin.get(
            "available"
        ):
            asn_details = []

            for asn in origin.get(
                "asns",
                [],
            ):
                asn_details.append(
                    lookup_asn(
                        asn
                    )
                )

            origin[
                "asn_details"
            ] = asn_details

        elif origin.get(
            "error"
        ):
            errors.append(
                {
                    "ip_address": address,
                    "source": "asn",
                    "error": origin[
                        "error"
                    ],
                }
            )

        asn_records.append(
            origin
        )

        ptr_result = reverse_dns_lookup(
            address
        )

        if ptr_result.get(
            "error"
        ):
            errors.append(
                {
                    "ip_address": address,
                    "source": "reverse_dns",
                    "error": ptr_result[
                        "error"
                    ],
                }
            )

        reverse_dns.append(
            ptr_result
        )

    unique_asns = sorted(
        {
            asn
            for record in asn_records
            for asn in record.get(
                "asns",
                [],
            )
        }
    )

    unique_network_names = sorted(
        {
            str(
                detail.get(
                    "network_name"
                )
            ).strip()
            for record in asn_records
            for detail in record.get(
                "asn_details",
                []
            )
            if detail.get(
                "network_name"
            )
        }
    )

    lookup_status = (
        "success"
        if public_addresses
        else (
            "limited"
            if all_addresses
            else "failed"
        )
    )

    return {
        "hostname": normalized,
        "lookup_status": lookup_status,
        "ipv4_addresses": (
            address_result[
                "ipv4_addresses"
            ]
        ),
        "ipv6_addresses": (
            address_result[
                "ipv6_addresses"
            ]
        ),
        "public_addresses": (
            public_addresses
        ),
        "private_or_special_addresses": (
            private_or_special
        ),
        "asn_records": asn_records,
        "unique_asns": unique_asns,
        "unique_network_names": (
            unique_network_names
        ),
        "reverse_dns": reverse_dns,
        "error_messages": errors,
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
            INSERT INTO network_observations (
                hostname,
                lookup_status,
                ipv4_addresses_json,
                ipv6_addresses_json,
                public_addresses_json,
                private_or_special_addresses_json,
                asn_records_json,
                unique_asns_json,
                unique_network_names_json,
                reverse_dns_json,
                error_messages_json,
                observed_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(hostname)
            DO UPDATE SET
                lookup_status = excluded.lookup_status,
                ipv4_addresses_json = excluded.ipv4_addresses_json,
                ipv6_addresses_json = excluded.ipv6_addresses_json,
                public_addresses_json = excluded.public_addresses_json,
                private_or_special_addresses_json =
                    excluded.private_or_special_addresses_json,
                asn_records_json = excluded.asn_records_json,
                unique_asns_json = excluded.unique_asns_json,
                unique_network_names_json =
                    excluded.unique_network_names_json,
                reverse_dns_json = excluded.reverse_dns_json,
                error_messages_json = excluded.error_messages_json,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at
            """,
            (
                observation[
                    "hostname"
                ],
                observation[
                    "lookup_status"
                ],
                json.dumps(
                    observation.get(
                        "ipv4_addresses",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "ipv6_addresses",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "public_addresses",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "private_or_special_addresses",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "asn_records",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "unique_asns",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "unique_network_names",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "reverse_dns",
                        [],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    observation.get(
                        "error_messages",
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
            "hostname"
        ]
    )

    if saved is None:
        raise IPASNIntelligenceError(
            "Network observation could not be saved."
        )

    return saved


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    mappings = {
        "ipv4_addresses_json": (
            "ipv4_addresses"
        ),
        "ipv6_addresses_json": (
            "ipv6_addresses"
        ),
        "public_addresses_json": (
            "public_addresses"
        ),
        "private_or_special_addresses_json": (
            "private_or_special_addresses"
        ),
        "asn_records_json": (
            "asn_records"
        ),
        "unique_asns_json": (
            "unique_asns"
        ),
        "unique_network_names_json": (
            "unique_network_names"
        ),
        "reverse_dns_json": (
            "reverse_dns"
        ),
        "error_messages_json": (
            "error_messages"
        ),
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

    return result


def get_observation(
    hostname: str,
) -> dict[str, Any] | None:
    initialize_database()

    normalized = normalize_hostname(
        hostname
    )

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM network_observations
            WHERE hostname = ?
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


def lookup_hostname(
    hostname: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    normalized = normalize_hostname(
        hostname
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

    observation = analyze_hostname(
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
            FROM network_observations
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
            FROM network_observations
            """
        ).fetchone()["count"]

        successful = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM network_observations
            WHERE lookup_status = 'success'
            """
        ).fetchone()["count"]

    observations = list_observations(
        limit=5000
    )

    unique_asns = {
        asn
        for observation in observations
        for asn in observation.get(
            "unique_asns",
            []
        )
    }

    unique_networks = {
        name
        for observation in observations
        for name in observation.get(
            "unique_network_names",
            []
        )
    }

    return {
        "observed_hostnames": int(
            total
        ),
        "successful_lookups": int(
            successful
        ),
        "limited_or_failed": int(
            total - successful
        ),
        "unique_asns": len(
            unique_asns
        ),
        "unique_network_names": len(
            unique_networks
        ),
    }
