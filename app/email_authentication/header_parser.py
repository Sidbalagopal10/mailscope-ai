from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any


SUPPORTED_METHODS = {
    "spf",
    "dkim",
    "dmarc",
    "arc",
}

PASS_RESULTS = {
    "pass",
    "bestguesspass",
}

FAIL_RESULTS = {
    "fail",
    "softfail",
    "hardfail",
    "permerror",
}

NEUTRAL_RESULTS = {
    "none",
    "neutral",
    "temperror",
    "policy",
    "unknown",
}


def normalize_headers(
    headers: Any,
) -> list[dict[str, str]]:
    """
    Accept Gmail API header dictionaries, a dictionary mapping,
    or a raw header string.
    """
    normalized: list[dict[str, str]] = []

    if isinstance(headers, list):
        for item in headers:
            if not isinstance(item, dict):
                continue

            name = str(
                item.get("name", "")
            ).strip()

            value = str(
                item.get("value", "")
            ).strip()

            if name:
                normalized.append(
                    {
                        "name": name,
                        "value": value,
                    }
                )

        return normalized

    if isinstance(headers, dict):
        for name, value in headers.items():
            if isinstance(value, list):
                for entry in value:
                    normalized.append(
                        {
                            "name": str(name),
                            "value": str(entry),
                        }
                    )
            else:
                normalized.append(
                    {
                        "name": str(name),
                        "value": str(value),
                    }
                )

        return normalized

    if isinstance(headers, str):
        current_name: str | None = None
        current_value: list[str] = []

        for line in headers.splitlines():
            if (
                line.startswith((" ", "\t"))
                and current_name
            ):
                current_value.append(
                    line.strip()
                )
                continue

            if current_name:
                normalized.append(
                    {
                        "name": current_name,
                        "value": " ".join(
                            current_value
                        ).strip(),
                    }
                )

            if ":" not in line:
                current_name = None
                current_value = []
                continue

            current_name, value = line.split(
                ":",
                1,
            )

            current_name = current_name.strip()
            current_value = [
                value.strip()
            ]

        if current_name:
            normalized.append(
                {
                    "name": current_name,
                    "value": " ".join(
                        current_value
                    ).strip(),
                }
            )

    return normalized


def header_values(
    headers: list[dict[str, str]],
    name: str,
) -> list[str]:
    target = name.lower()

    return [
        item["value"]
        for item in headers
        if item["name"].lower() == target
    ]


def first_header(
    headers: list[dict[str, str]],
    name: str,
) -> str | None:
    values = header_values(
        headers,
        name,
    )

    return values[0] if values else None


def email_domain(
    value: str | None,
) -> str | None:
    if not value:
        return None

    _, address = parseaddr(
        value
    )

    if "@" not in address:
        return None

    domain = address.rsplit(
        "@",
        1,
    )[1].strip().lower().rstrip(".")

    return domain or None


def normalize_result(
    value: str | None,
) -> str:
    result = str(
        value or "unknown"
    ).strip().lower()

    result = result.split(
        "(",
        1,
    )[0].strip()

    if result in PASS_RESULTS:
        return "pass"

    if result in FAIL_RESULTS:
        return result

    if result in NEUTRAL_RESULTS:
        return result

    return "unknown"


def parse_property_tokens(
    text: str,
) -> dict[str, str]:
    properties: dict[str, str] = {}

    pattern = re.compile(
        r"""
        (?P<key>
            [a-zA-Z][a-zA-Z0-9_.-]*
        )
        \s*=\s*
        (?P<value>
            "(?:[^"\\]|\\.)*"
            |
            [^\s;]+
        )
        """,
        re.VERBOSE,
    )

    for match in pattern.finditer(
        text
    ):
        key = match.group(
            "key"
        ).lower()

        value = match.group(
            "value"
        ).strip().strip('"')

        properties[key] = value

    return properties


def parse_authentication_results_value(
    value: str,
    *,
    source_header: str,
) -> list[dict[str, Any]]:
    unfolded = re.sub(
        r"\s+",
        " ",
        str(value or ""),
    ).strip()

    if not unfolded:
        return []

    segments = [
        segment.strip()
        for segment in unfolded.split(";")
        if segment.strip()
    ]

    if not segments:
        return []

    authserv_id = segments[0]
    results: list[dict[str, Any]] = []

    method_pattern = re.compile(
        r"""
        ^
        (?P<method>
            spf|dkim|dmarc|arc
        )
        (?:/
            (?P<version>[0-9]+)
        )?
        \s*=\s*
        (?P<result>[a-zA-Z0-9_-]+)
        (?P<remainder>.*)
        $
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    for segment in segments[1:]:
        match = method_pattern.match(
            segment
        )

        if not match:
            continue

        method = match.group(
            "method"
        ).lower()

        result = normalize_result(
            match.group(
                "result"
            )
        )

        remainder = match.group(
            "remainder"
        ).strip()

        properties = parse_property_tokens(
            remainder
        )

        results.append(
            {
                "method": method,
                "result": result,
                "raw_result": match.group(
                    "result"
                ).lower(),
                "version": match.group(
                    "version"
                ),
                "properties": properties,
                "authserv_id": authserv_id,
                "source_header": source_header,
                "raw_segment": segment,
            }
        )

    return results


def parse_received_spf(
    values: list[str],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for value in values:
        match = re.match(
            r"^\s*([a-zA-Z0-9_-]+)",
            value,
        )

        if not match:
            continue

        results.append(
            {
                "method": "spf",
                "result": normalize_result(
                    match.group(1)
                ),
                "raw_result": match.group(
                    1
                ).lower(),
                "version": None,
                "properties": (
                    parse_property_tokens(
                        value
                    )
                ),
                "authserv_id": None,
                "source_header": (
                    "Received-SPF"
                ),
                "raw_segment": value,
            }
        )

    return results


def choose_method_result(
    records: list[dict[str, Any]],
    method: str,
) -> dict[str, Any]:
    matching = [
        record
        for record in records
        if record.get(
            "method"
        ) == method
    ]

    if not matching:
        return {
            "method": method,
            "result": "unknown",
            "available": False,
            "records": [],
        }

    precedence = {
        "pass": 6,
        "fail": 5,
        "hardfail": 5,
        "softfail": 4,
        "permerror": 3,
        "temperror": 2,
        "neutral": 1,
        "none": 1,
        "unknown": 0,
    }

    selected = max(
        matching,
        key=lambda item: precedence.get(
            item.get(
                "result",
                "unknown",
            ),
            0,
        ),
    )

    return {
        "method": method,
        "result": selected.get(
            "result",
            "unknown",
        ),
        "available": True,
        "selected_record": selected,
        "records": matching,
    }


def parse_email_authentication(
    headers: Any,
) -> dict[str, Any]:
    normalized_headers = normalize_headers(
        headers
    )

    records: list[dict[str, Any]] = []

    for value in header_values(
        normalized_headers,
        "Authentication-Results",
    ):
        records.extend(
            parse_authentication_results_value(
                value,
                source_header=(
                    "Authentication-Results"
                ),
            )
        )

    for value in header_values(
        normalized_headers,
        "ARC-Authentication-Results",
    ):
        records.extend(
            parse_authentication_results_value(
                value,
                source_header=(
                    "ARC-Authentication-Results"
                ),
            )
        )

    records.extend(
        parse_received_spf(
            header_values(
                normalized_headers,
                "Received-SPF",
            )
        )
    )

    from_value = first_header(
        normalized_headers,
        "From",
    )

    return_path = first_header(
        normalized_headers,
        "Return-Path",
    )

    message_id = first_header(
        normalized_headers,
        "Message-ID",
    )

    method_results = {
        method: choose_method_result(
            records,
            method,
        )
        for method in sorted(
            SUPPORTED_METHODS
        )
    }

    return {
        "from_header": from_value,
        "from_domain": email_domain(
            from_value
        ),
        "return_path": return_path,
        "return_path_domain": email_domain(
            return_path
        ),
        "message_id": message_id,
        "authentication_results_present": bool(
            header_values(
                normalized_headers,
                "Authentication-Results",
            )
        ),
        "arc_authentication_results_present": bool(
            header_values(
                normalized_headers,
                "ARC-Authentication-Results",
            )
        ),
        "spf": method_results["spf"],
        "dkim": method_results["dkim"],
        "dmarc": method_results["dmarc"],
        "arc": method_results["arc"],
        "records": records,
        "header_count": len(
            normalized_headers
        ),
    }
