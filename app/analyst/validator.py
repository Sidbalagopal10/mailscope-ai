from __future__ import annotations

from typing import Any

from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.analyst.report_schema import (
    VALID_VERDICTS,
)


def valid_evidence_ids(
    evidence: InvestigationEvidence,
) -> set[str]:
    return {
        f"E{index}"
        for index in range(
            1,
            len(
                evidence.findings
            )
            + 1,
        )
    }


def validate_report(
    *,
    payload: dict[str, Any],
    evidence: InvestigationEvidence,
) -> list[str]:
    errors = []

    verdict = payload.get(
        "verdict"
    )

    if verdict not in VALID_VERDICTS:
        errors.append(
            "Invalid verdict."
        )

    confidence = payload.get(
        "confidence"
    )

    if not isinstance(
        confidence,
        (
            int,
            float,
        ),
    ):
        errors.append(
            "Confidence must be numeric."
        )

    elif not (
        0
        <= float(
            confidence
        )
        <= 100
    ):
        errors.append(
            "Confidence must be between 0 and 100."
        )

    findings = payload.get(
        "findings"
    )

    if not isinstance(
        findings,
        list,
    ):
        errors.append(
            "Findings must be a list."
        )

        findings = []

    allowed_ids = valid_evidence_ids(
        evidence
    )

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        if not isinstance(
            finding,
            dict,
        ):
            errors.append(
                f"Finding {index} is not an object."
            )

            continue

        cited = finding.get(
            "evidence_ids",
            [],
        )

        if not isinstance(
            cited,
            list,
        ):
            errors.append(
                f"Finding {index} evidence_ids "
                "must be a list."
            )

            continue

        if not cited:
            errors.append(
                f"Finding {index} cites no evidence."
            )

        unknown = (
            set(
                str(
                    item
                )
                for item in cited
            )
            - allowed_ids
        )

        if unknown:
            errors.append(
                f"Finding {index} cites unknown "
                f"evidence IDs: "
                + ", ".join(
                    sorted(
                        unknown
                    )
                )
            )

    investigation_id = payload.get(
        "investigation_id"
    )

    if (
        investigation_id
        != evidence.investigation_id
    ):
        errors.append(
            "Investigation ID does not match "
            "the evidence package."
        )

    return errors
