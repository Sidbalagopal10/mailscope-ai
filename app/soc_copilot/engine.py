import re
from typing import Any

from app.soc_copilot.models import CopilotAnswer


EVIDENCE_PATTERN = re.compile(
    r"\bE(\d+)\b",
    re.IGNORECASE,
)


def _evidence_items(
    report: dict[str, Any],
):
    evidence = (
        report.get("evidence", {})
        or {}
    )

    findings = (
        evidence.get("findings", [])
        or []
    )

    items = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        if not isinstance(finding, dict):
            continue

        items.append(
            {
                "id": f"E{index}",
                "title": str(
                    finding.get(
                        "title",
                        "Evidence",
                    )
                ),
                "description": str(
                    finding.get(
                        "description",
                        "",
                    )
                ),
                "source": str(
                    finding.get(
                        "source",
                        "unknown",
                    )
                ),
            }
        )

    return items


def _intent(question: str) -> str:
    q = question.lower()

    if re.search(
        r"\bE\d+\b",
        question,
        re.IGNORECASE,
    ):
        return "explain_evidence"

    if any(
        phrase in q
        for phrase in [
            "why phishing",
            "why was",
            "why is this",
            "classified",
            "verdict",
        ]
    ):
        return "explain_verdict"

    if any(
        phrase in q
        for phrase in [
            "indicator",
            "ioc",
            "observable",
        ]
    ):
        return "indicators"

    if any(
        phrase in q
        for phrase in [
            "related",
            "campaign",
            "similar investigation",
        ]
    ):
        return "related_activity"

    if any(
        phrase in q
        for phrase in [
            "what should",
            "next step",
            "recommend",
            "response",
            "action",
        ]
    ):
        return "actions"

    if any(
        phrase in q
        for phrase in [
            "sigma",
            "detection rule",
            "detection guidance",
        ]
    ):
        return "detection_guidance"

    if any(
        phrase in q
        for phrase in [
            "summarize",
            "summary",
            "escalation",
        ]
    ):
        return "summary"

    return "unsupported"


def _base_metadata():
    return {
        "copilot_version": "soc-copilot-v1.0",
        "grounded": True,
        "deterministic_fallback": True,
        "ai_used": False,
        "external_lookup_used": False,
        "verdict_modified": False,
        "threat_actor_attributed": False,
        "unsupported_facts_must_be_refused": True,
    }


def answer_question(
    report: dict[str, Any],
    question: str,
    campaigns: list[dict] | None = None,
) -> CopilotAnswer:
    question = str(question).strip()

    investigation_id = str(
        report.get(
            "investigation_id",
            "unknown",
        )
    )

    evidence = _evidence_items(
        report
    )

    evidence_lookup = {
        item["id"]: item
        for item in evidence
    }

    intent = _intent(
        question
    )

    related = []

    for campaign in campaigns or []:
        for related_id in (
            campaign.get(
                "investigation_ids",
                [],
            )
            or []
        ):
            related_id = str(
                related_id
            )

            if (
                related_id
                != investigation_id
                and related_id
                not in related
            ):
                related.append(
                    related_id
                )

    if intent == "explain_evidence":
        match = EVIDENCE_PATTERN.search(
            question
        )

        evidence_id = (
            f"E{match.group(1)}"
            if match
            else ""
        )

        item = evidence_lookup.get(
            evidence_id
        )

        if item is None:
            answer = (
                f"{evidence_id or 'That evidence ID'} "
                "is not present in the canonical investigation evidence. "
                "I will not invent an explanation for evidence that is absent."
            )

            citations = []

        else:
            answer = (
                f"{evidence_id} — {item['title']}: "
                f"{item['description']} "
                f"Source: {item['source']}."
            )

            citations = [
                evidence_id
            ]

    elif intent == "explain_verdict":
        verdict = str(
            report.get(
                "verdict",
                "unknown",
            )
        ).replace(
            "_",
            " ",
        )

        severity = float(
            report.get(
                "severity",
                0.0,
            )
            or 0.0
        )

        risk_level = str(
            report.get(
                "risk_level",
                "UNKNOWN",
            )
        )

        findings = (
            report.get(
                "findings",
                [],
            )
            or []
        )

        cited_ids = []

        reasons = []

        for finding in findings:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            explanation = str(
                finding.get(
                    "explanation",
                    "",
                )
            ).strip()

            if explanation:
                reasons.append(
                    explanation
                )

            for evidence_id in (
                finding.get(
                    "evidence_ids",
                    [],
                )
                or []
            ):
                evidence_id = str(
                    evidence_id
                )

                if (
                    evidence_id
                    in evidence_lookup
                    and evidence_id
                    not in cited_ids
                ):
                    cited_ids.append(
                        evidence_id
                    )

        if not reasons:
            reasons = [
                item["description"]
                for item in evidence
            ]

            cited_ids = [
                item["id"]
                for item in evidence
            ]

        reason_text = (
            " ".join(
                reasons[:4]
            )
            if reasons
            else (
                "The canonical report does not contain "
                "sufficient evidence to explain the verdict further."
            )
        )

        answer = (
            f"The deterministic investigation verdict is "
            f"'{verdict}' with severity {severity:.1f}/10 "
            f"and risk level {risk_level}. "
            f"{reason_text}"
        )

        citations = cited_ids

    elif intent == "indicators":
        iocs = (
            report.get(
                "iocs",
                [],
            )
            or []
        )

        if not iocs:
            answer = (
                "The canonical report contains no extracted indicators."
            )

        else:
            parts = []

            for ioc in iocs[:12]:
                if not isinstance(
                    ioc,
                    dict,
                ):
                    continue

                parts.append(
                    str(
                        ioc.get(
                            "type",
                            "observable",
                        )
                    )
                    + ": "
                    + str(
                        ioc.get(
                            "value",
                            "",
                        )
                    )
                )

            answer = (
                "The investigation contains "
                + str(len(iocs))
                + " extracted indicator(s): "
                + "; ".join(parts)
                + "."
            )

        citations = []

    elif intent == "related_activity":
        if related:
            answer = (
                "Campaign correlation links this investigation "
                "to the following historical investigation(s): "
                + ", ".join(related)
                + ". This indicates shared evidence, not proof "
                "of a common threat actor."
            )

        else:
            answer = (
                "No related investigations are currently present "
                "in the campaign correlation store for this investigation."
            )

        citations = []

    elif intent == "actions":
        recommendations = (
            report.get(
                "recommendations",
                [],
            )
            or []
        )

        if recommendations:
            answer = (
                "Recommended analyst actions from the canonical report: "
                + "; ".join(
                    str(item)
                    for item in recommendations
                )
            )

        else:
            answer = (
                "The canonical report contains no explicit "
                "recommended analyst actions."
            )

        citations = []

    elif intent == "summary":
        executive_summary = str(
            report.get(
                "executive_summary",
                "",
            )
        ).strip()

        verdict = str(
            report.get(
                "verdict",
                "unknown",
            )
        ).replace(
            "_",
            " ",
        )

        severity = float(
            report.get(
                "severity",
                0.0,
            )
            or 0.0
        )

        if executive_summary:
            answer = (
                f"Investigation {investigation_id}: "
                f"{executive_summary} "
                f"Verdict: {verdict}. "
                f"Deterministic severity: {severity:.1f}/10."
            )

        else:
            answer = (
                f"Investigation {investigation_id} has verdict "
                f"{verdict} and deterministic severity "
                f"{severity:.1f}/10."
            )

        citations = [
            item["id"]
            for item in evidence
        ]

    elif intent == "detection_guidance":
        iocs = (
            report.get(
                "iocs",
                [],
            )
            or []
        )

        domains = []
        urls = []
        emails = []
        hashes = []

        for ioc in iocs:
            if not isinstance(
                ioc,
                dict,
            ):
                continue

            ioc_type = str(
                ioc.get(
                    "type",
                    "",
                )
            ).lower()

            value = str(
                ioc.get(
                    "value",
                    "",
                )
            )

            if not value:
                continue

            if ioc_type in {
                "domain",
                "hostname",
            }:
                domains.append(
                    value
                )

            elif ioc_type == "url":
                urls.append(
                    value
                )

            elif ioc_type in {
                "email",
                "sender",
            }:
                emails.append(
                    value
                )

            elif ioc_type in {
                "md5",
                "sha1",
                "sha256",
            }:
                hashes.append(
                    value
                )

        guidance = []

        if domains:
            guidance.append(
                "monitor DNS/proxy telemetry for exact domain matches: "
                + ", ".join(
                    domains[:5]
                )
            )

        if urls:
            guidance.append(
                "monitor web gateway telemetry for exact URL matches"
            )

        if emails:
            guidance.append(
                "search mail telemetry for exact sender/address matches"
            )

        if hashes:
            guidance.append(
                "search endpoint telemetry for exact file hash matches"
            )

        if guidance:
            answer = (
                "Evidence-backed defensive guidance: "
                + "; ".join(
                    guidance
                )
                + ". These are defensive hunt ideas, not "
                "automatically deployable production rules."
            )

        else:
            answer = (
                "There are not enough supported observables in the "
                "canonical report to generate evidence-backed detection guidance."
            )

        citations = []

    else:
        answer = (
            "I can answer grounded questions about this investigation's "
            "verdict, evidence IDs, indicators, related campaign activity, "
            "recommended actions, escalation summary, and defensive "
            "detection guidance. I will not invent unsupported facts."
        )

        citations = []

    return CopilotAnswer(
        investigation_id=investigation_id,
        question=question,
        intent=intent,
        answer=answer,
        evidence_ids=citations,
        related_investigations=related,
        metadata=_base_metadata(),
    )
