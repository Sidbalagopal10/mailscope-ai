from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from app.campaign_detection.models import CorrelationArtifact
from app.reports.models import InvestigationReport


SUPPORTED_TYPES = {
    "url",
    "hostname",
    "domain",
    "ip",
    "email",
    "sender",
    "md5",
    "sha1",
    "sha256",
}


def canonical_artifact_type(
    artifact_type: str,
) -> str:
    kind = str(
        artifact_type or ""
    ).strip().lower()

    if kind == "hostname":
        return "domain"

    if kind == "sender":
        return "email"

    return kind


def _normalize_url(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return cleaned.lower()

    hostname = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    if not hostname:
        return cleaned.lower()

    scheme = (
        parsed.scheme
        or "https"
    ).lower()

    try:
        port = parsed.port
    except ValueError:
        return cleaned.lower()

    netloc = hostname

    is_default_port = (
        scheme == "http"
        and port == 80
    ) or (
        scheme == "https"
        and port == 443
    )

    if (
        port is not None
        and not is_default_port
    ):
        netloc = f"{hostname}:{port}"

    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def normalize_artifact_value(
    artifact_type: str,
    value: str,
) -> str:
    kind = canonical_artifact_type(
        artifact_type
    )

    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if kind == "url":
        return _normalize_url(cleaned)

    if kind == "domain":
        return cleaned.lower().rstrip(".")

    if kind == "ip":
        try:
            return str(
                ipaddress.ip_address(
                    cleaned
                )
            )
        except ValueError:
            return ""

    if kind in {
        "email",
        "md5",
        "sha1",
        "sha256",
    }:
        return cleaned.lower()

    return cleaned.lower()


def artifacts_from_report(
    report: InvestigationReport,
) -> list[CorrelationArtifact]:
    """
    Consume only observables already present in the canonical
    InvestigationReport.

    No enrichment, network requests or AI are performed here.
    """

    output: list[CorrelationArtifact] = []
    seen: set[tuple[str, str]] = set()

    for ioc in report.iocs:
        original_type = str(
            ioc.type or ""
        ).strip().lower()

        if original_type not in SUPPORTED_TYPES:
            continue

        kind = canonical_artifact_type(
            original_type
        )

        value = normalize_artifact_value(
            kind,
            ioc.value,
        )

        if not value:
            continue

        key = (
            kind,
            value,
        )

        if key in seen:
            continue

        seen.add(key)

        output.append(
            CorrelationArtifact(
                type=kind,
                value=value,
                source=str(
                    ioc.source
                    or "investigation_report"
                ),
                confidence=(
                    float(ioc.confidence)
                    if ioc.confidence is not None
                    else None
                ),
            )
        )

    return output
