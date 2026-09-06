from __future__ import annotations

from pathlib import Path

from app.reports.models import (
    InvestigationReport,
)


def export_markdown(
    report: InvestigationReport,
    *,
    directory: Path,
) -> Path:
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        directory
        / "report.md"
    )

    lines = [
        "# AI Security Investigation Report",
        "",
        f"**Investigation ID:** `{report.investigation_id}`",
        "",
        f"**Target:** `{report.target}`",
        "",
        f"**Verdict:** **{report.verdict.upper()}**",
        "",
        f"**Confidence:** {report.confidence:.1f}%",
        "",
        f"**Core Severity:** {report.severity:.1f}/10",
        "",
        f"**Risk Level:** {report.risk_level}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Identity Assessment",
        "",
        f"- Known identity: `{report.identity.get('known')}`",
        f"- Organization: `{report.identity.get('organization') or 'Unknown'}`",
        f"- State: `{report.identity.get('state')}`",
        f"- Confidence: `{report.identity.get('confidence')}`",
        "",
        "## Technical Findings",
        "",
    ]

    if report.findings:
        for index, finding in enumerate(
            report.findings,
            start=1,
        ):
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    finding.explanation,
                    "",
                    f"**Severity:** {finding.severity}",
                    "",
                    "**Evidence:** "
                    + ", ".join(
                        finding.evidence_ids
                    ),
                    "",
                ]
            )

    else:
        lines.extend(
            [
                "No analyst findings were produced.",
                "",
            ]
        )

    lines.extend(
        [
            "## Indicators of Compromise / Observables",
            "",
        ]
    )

    if report.iocs:
        lines.extend(
            [
                "| Type | Value | Source |",
                "|---|---|---|",
            ]
        )

        for ioc in report.iocs:
            lines.append(
                f"| {ioc.type} | `{ioc.value}` | {ioc.source} |"
            )

    else:
        lines.append(
            "No IOCs were extracted."
        )

    lines.extend(
        [
            "",
            "## MITRE ATT&CK",
            "",
        ]
    )

    if report.mitre_attack:
        for item in report.mitre_attack:
            lines.append(
                "- **"
                + str(
                    item.get(
                        "technique_id",
                        "Unknown"
                    )
                )
                + "** — "
                + str(
                    item.get(
                        "technique_name",
                        "Unknown"
                    )
                )
                + ": "
                + str(
                    item.get(
                        "reason",
                        ""
                    )
                )
            )

    else:
        lines.append(
            "No MITRE ATT&CK techniques were assigned."
        )

    lines.extend(
        [
            "",
            "## Investigation Timeline",
            "",
        ]
    )

    for event in report.timeline:
        lines.extend(
            [
                f"### {event.timestamp}",
                "",
                f"**{event.title}**",
                "",
                event.description,
                "",
                f"Source: `{event.source}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Recommended Actions",
            "",
        ]
    )

    if report.recommendations:
        for action in report.recommendations:
            lines.append(
                f"- {action}"
            )

    else:
        lines.append(
            "- No actions were generated."
        )

    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )

    if report.limitations:
        for limitation in report.limitations:
            lines.append(
                f"- {limitation}"
            )

    else:
        lines.append(
            "- No explicit analyst limitations were reported."
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "### Investigation Metadata",
            "",
            f"- Analyst model: `{report.analyst_model}`",
            f"- Grounded AI: `{report.metadata.get('grounded_ai')}`",
            f"- Core release: `{report.metadata.get('core_release')}`",
            "",
        ]
    )

    path.write_text(
        "\n".join(
            lines
        ),
        encoding="utf-8",
    )

    return path
