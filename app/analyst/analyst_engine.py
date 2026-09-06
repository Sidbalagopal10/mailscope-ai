from __future__ import annotations

from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.analyst.prompt_engine import (
    build_analyst_prompt,
)
from app.analyst.providers.factory import (
    get_ai_provider,
)
from app.analyst.report_schema import (
    AnalystFinding,
    AnalystReport,
)
from app.analyst.validator import (
    validate_report,
)


class GroundingValidationError(
    RuntimeError
):
    pass


def analyze_evidence(
    evidence: InvestigationEvidence,
) -> AnalystReport:
    prompt = build_analyst_prompt(
        evidence
    )

    provider = (
        get_ai_provider()
    )

    payload = provider.generate_json(
        prompt
    )

    errors = validate_report(
        payload=payload,
        evidence=evidence,
    )

    if errors:
        raise GroundingValidationError(
            "AI report failed grounding validation: "
            + "; ".join(
                errors
            )
        )

    findings = []

    for item in payload.get(
        "findings",
        [],
    ):
        findings.append(
            AnalystFinding(
                title=str(
                    item.get(
                        "title",
                        "",
                    )
                ),

                explanation=str(
                    item.get(
                        "explanation",
                        "",
                    )
                ),

                evidence_ids=[
                    str(
                        value
                    )
                    for value in item.get(
                        "evidence_ids",
                        []
                    )
                ],

                severity=str(
                    item.get(
                        "severity",
                        "info",
                    )
                ),
            )
        )

    return AnalystReport(
        investigation_id=(
            evidence.investigation_id
        ),

        verdict=str(
            payload[
                "verdict"
            ]
        ),

        confidence=float(
            payload[
                "confidence"
            ]
        ),

        executive_summary=str(
            payload.get(
                "executive_summary",
                "",
            )
        ),

        findings=findings,

        recommended_actions=[
            str(
                value
            )
            for value in payload.get(
                "recommended_actions",
                []
            )
        ],

        mitre_attack=[
            dict(
                item
            )
            for item in payload.get(
                "mitre_attack",
                []
            )
            if isinstance(
                item,
                dict,
            )
        ],

        limitations=[
            str(
                value
            )
            for value in payload.get(
                "limitations",
                []
            )
        ],

        model=(
            provider.provider_name
            + ":"
            + provider.model_name
        ),

        grounded=True,

        validation_errors=[],

        metadata={
            "evidence_grounded": True,

            "security_facts_generated_by_ai": (
                False
            ),

            "provider": (
                provider.provider_name
            ),
        },
    )
