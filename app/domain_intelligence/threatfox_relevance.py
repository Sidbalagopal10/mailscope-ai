from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit


IOC_FIELD_TERMS = {
    "ioc",
    "ioc_value",
    "indicator",
    "indicator_value",
    "host",
    "hostname",
    "domain",
    "url",
}


def normalize_hostname(
    value: str | None,
) -> str:
    cleaned = str(
        value or ""
    ).strip().lower().rstrip(".")

    if not cleaned:
        return ""

    if "://" in cleaned:
        try:
            cleaned = (
                urlsplit(
                    cleaned
                ).hostname
                or ""
            )
        except ValueError:
            return ""

    elif "/" in cleaned:
        try:
            cleaned = (
                urlsplit(
                    "https://" + cleaned
                ).hostname
                or ""
            )
        except ValueError:
            return ""

    cleaned = cleaned.strip().lower().rstrip(".")

    if cleaned.startswith(
        "*."
    ):
        cleaned = cleaned[2:]

    if not cleaned:
        return ""

    try:
        return cleaned.encode(
            "idna"
        ).decode(
            "ascii"
        )
    except UnicodeError:
        return ""


def hostname_from_value(
    value: str | None,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if cleaned.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):
        return normalize_hostname(
            cleaned
        )

    candidate = cleaned.split(
        "|",
        1,
    )[0].strip()

    candidate = candidate.split(
        " ",
        1,
    )[0].strip()

    if candidate.count(
        ":"
    ) == 1:
        host, possible_port = candidate.rsplit(
            ":",
            1,
        )

        if possible_port.isdigit():
            candidate = host

    return normalize_hostname(
        candidate
    )


def is_same_or_true_subdomain(
    candidate_host: str,
    requested_host: str,
) -> bool:
    candidate = normalize_hostname(
        candidate_host
    )

    requested = normalize_hostname(
        requested_host
    )

    if not candidate or not requested:
        return False

    try:
        candidate_ip = ipaddress.ip_address(
            candidate
        )

        requested_ip = ipaddress.ip_address(
            requested
        )

        return candidate_ip == requested_ip

    except ValueError:
        pass

    return bool(
        candidate == requested
        or candidate.endswith(
            "." + requested
        )
    )


def collect_ioc_values(
    value: Any,
    *,
    parent_key: str = "",
) -> list[str]:
    results: list[str] = []

    if isinstance(
        value,
        dict,
    ):
        for key, child in value.items():
            lowered_key = str(
                key
            ).strip().lower()

            key_is_relevant = bool(
                lowered_key in IOC_FIELD_TERMS
                or any(
                    term in lowered_key
                    for term in (
                        "ioc",
                        "indicator",
                        "hostname",
                    )
                )
            )

            if (
                key_is_relevant
                and isinstance(
                    child,
                    str,
                )
            ):
                cleaned = child.strip()

                if cleaned:
                    results.append(
                        cleaned
                    )

            results.extend(
                collect_ioc_values(
                    child,
                    parent_key=lowered_key,
                )
            )

    elif isinstance(
        value,
        list,
    ):
        for child in value:
            results.extend(
                collect_ioc_values(
                    child,
                    parent_key=parent_key,
                )
            )

    return list(
        dict.fromkeys(
            results
        )
    )


def relevant_iocs(
    threatfox_payload: dict[str, Any] | None,
    requested_host: str,
) -> list[dict[str, str]]:
    payload = (
        threatfox_payload
        if isinstance(
            threatfox_payload,
            dict,
        )
        else {}
    )

    requested = normalize_hostname(
        requested_host
    )

    matches: list[
        dict[str, str]
    ] = []

    for raw_value in collect_ioc_values(
        payload
    ):
        candidate_host = hostname_from_value(
            raw_value
        )

        if is_same_or_true_subdomain(
            candidate_host,
            requested,
        ):
            matches.append(
                {
                    "raw_ioc": raw_value,
                    "candidate_host": (
                        candidate_host
                    ),
                    "requested_host": requested,
                    "match_type": (
                        "exact"
                        if candidate_host
                        == requested
                        else "true_subdomain"
                    ),
                }
            )

    return matches


def threatfox_match_is_relevant(
    threatfox_payload: dict[str, Any] | None,
    requested_host: str,
) -> bool:
    return bool(
        relevant_iocs(
            threatfox_payload,
            requested_host,
        )
    )


def sanitize_threatfox_payload(
    threatfox_payload: dict[str, Any] | None,
    requested_host: str,
) -> dict[str, Any]:
    payload = dict(
        threatfox_payload or {}
    )

    matches = relevant_iocs(
        payload,
        requested_host,
    )

    relevant = bool(
        matches
    )

    original_match_claimed = bool(
        payload.get(
            "matched",
            False,
        )
        or payload.get(
            "match",
            False,
        )
        or payload.get(
            "detected",
            False,
        )
    )

    payload[
        "original_match_claimed"
    ] = original_match_claimed

    payload[
        "relevance_validated"
    ] = True

    payload[
        "relevant_exact_match"
    ] = relevant

    payload[
        "relevant_iocs"
    ] = matches

    payload[
        "matched"
    ] = bool(
        original_match_claimed
        and relevant
    )

    if original_match_claimed and not relevant:
        payload[
            "false_positive_filtered"
        ] = True

        payload[
            "applied_score_adjustment"
        ] = 0.0

        payload[
            "risk_adjustment"
        ] = 0.0

        payload[
            "requested_score_adjustment"
        ] = 0.0

        payload[
            "filter_reason"
        ] = (
            "ThreatFox returned no IOC whose hostname exactly "
            "matched the requested hostname or a true subdomain."
        )

    else:
        payload[
            "false_positive_filtered"
        ] = False

    return payload
