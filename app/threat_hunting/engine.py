from pathlib import Path
from typing import Any

from app.threat_hunting.models import (
    HuntMatch,
    HuntResult,
)
from app.threat_hunting.normalization import (
    normalize_type,
    normalize_value,
)
from app.threat_hunting.report_loader import (
    load_investigation_reports,
)


SUPPORTED_TYPES = {
    "url",
    "domain",
    "ip",
    "email",
    "md5",
    "sha1",
    "sha256",
    "investigation_id",
}


def _report_observables(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    observables: list[
        dict[str, Any]
    ] = []

    investigation_id = str(
        report.get(
            "investigation_id",
            "",
        )
    )

    if investigation_id:
        observables.append(
            {
                "type": (
                    "investigation_id"
                ),
                "value": (
                    investigation_id
                ),
                "source": "report",
                "confidence": None,
            }
        )

    target = str(
        report.get(
            "target",
            "",
        )
        or ""
    )

    target_type = normalize_type(
        report.get(
            "target_type"
        )
    )

    if (
        target
        and target_type
        in SUPPORTED_TYPES
    ):
        observables.append(
            {
                "type": target_type,
                "value": target,
                "source": (
                    "report_target"
                ),
                "confidence": None,
            }
        )

    identity = (
        report.get(
            "identity",
            {}
        )
        or {}
    )

    canonical_domain = (
        identity.get(
            "canonical_domain"
        )
    )

    if canonical_domain:
        observables.append(
            {
                "type": "domain",
                "value": str(
                    canonical_domain
                ),
                "source": (
                    "identity"
                ),
                "confidence": (
                    identity.get(
                        "confidence"
                    )
                ),
            }
        )

    for ioc in (
        report.get(
            "iocs",
            []
        )
        or []
    ):
        if not isinstance(
            ioc,
            dict,
        ):
            continue

        observable_type = (
            normalize_type(
                ioc.get(
                    "type"
                )
            )
        )

        value = ioc.get(
            "value"
        )

        if (
            observable_type
            not in SUPPORTED_TYPES
            or value is None
        ):
            continue

        observables.append(
            {
                "type": (
                    observable_type
                ),
                "value": str(
                    value
                ),
                "source": str(
                    ioc.get(
                        "source",
                        "ioc",
                    )
                ),
                "confidence": (
                    ioc.get(
                        "confidence"
                    )
                ),
            }
        )

    return observables


def hunt_reports(
    query: str,
    observable_type: str | None = None,
    report_root: Path | str = (
        "data/investigations/reports"
    ),
) -> HuntResult:
    """
    Deterministically search historical canonical reports.

    Threat hunting does not rerun phishing detection,
    enrichment, AI analysis, or campaign attribution.
    """

    query = str(
        query
    ).strip()

    normalized_type = (
        normalize_type(
            observable_type
        )
    )

    if not query:
        return HuntResult(
            query="",
            observable_type=(
                normalized_type
            ),
            metadata={
                "engine_version": (
                    "threat-hunting-v1.0"
                ),
                "deterministic": True,
                "ai_used": False,
                "external_lookup_used": (
                    False
                ),
                "verdict_modified": False,
            },
        )

    if (
        normalized_type
        and normalized_type
        not in SUPPORTED_TYPES
    ):
        raise ValueError(
            "Unsupported observable type: "
            + normalized_type
        )

    reports = (
        load_investigation_reports(
            report_root
        )
    )

    matches: list[
        HuntMatch
    ] = []

    seen: set[
        tuple[str, str, str]
    ] = set()

    for report in reports:
        for observable in (
            _report_observables(
                report
            )
        ):
            current_type = (
                observable["type"]
            )

            if (
                normalized_type
                and current_type
                != normalized_type
            ):
                continue

            normalized_query = (
                normalize_value(
                    current_type,
                    query,
                )
            )

            normalized_observable = (
                normalize_value(
                    current_type,
                    observable[
                        "value"
                    ],
                )
            )

            if (
                normalized_query
                != normalized_observable
            ):
                continue

            key = (
                str(
                    report.get(
                        "investigation_id",
                        "",
                    )
                ),
                current_type,
                normalized_observable,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            confidence = (
                observable.get(
                    "confidence"
                )
            )

            try:
                confidence_value = (
                    float(
                        confidence
                    )
                    if confidence
                    is not None
                    else None
                )
            except (
                TypeError,
                ValueError,
            ):
                confidence_value = (
                    None
                )

            matches.append(
                HuntMatch(
                    investigation_id=str(
                        report.get(
                            "investigation_id",
                            "",
                        )
                    ),
                    target=str(
                        report.get(
                            "target",
                            "",
                        )
                    ),
                    created_at=str(
                        report.get(
                            "created_at",
                            "",
                        )
                    ),
                    verdict=str(
                        report.get(
                            "verdict",
                            "unknown",
                        )
                    ),
                    severity=float(
                        report.get(
                            "severity",
                            0.0,
                        )
                        or 0.0
                    ),
                    risk_level=str(
                        report.get(
                            "risk_level",
                            "UNKNOWN",
                        )
                    ),
                    observable_type=(
                        current_type
                    ),
                    observable_value=(
                        observable[
                            "value"
                        ]
                    ),
                    source=str(
                        observable.get(
                            "source",
                            "unknown",
                        )
                    ),
                    confidence=(
                        confidence_value
                    ),
                )
            )

    matches.sort(
        key=lambda item: (
            item.created_at,
            item.investigation_id,
        ),
        reverse=True,
    )

    return HuntResult(
        query=query,
        observable_type=(
            normalized_type
        ),
        matches=matches,
        scanned_reports=len(
            reports
        ),
        metadata={
            "engine_version": (
                "threat-hunting-v1.0"
            ),
            "deterministic": True,
            "ai_used": False,
            "external_lookup_used": False,
            "verdict_modified": False,
            "historical_reports_only": (
                True
            ),
        },
    )
