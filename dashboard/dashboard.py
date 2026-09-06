from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
import streamlit as st


# ============================================================
# Configuration
# ============================================================

API_BASE_URL = "http://127.0.0.1:8000"

PROJECT_ROOT = (
    Path(__file__).resolve().parents[1]
)

BENCHMARK_REPORT = (
    PROJECT_ROOT
    / "data/evaluation/latest_benchmark_report.json"
)


st.set_page_config(
    page_title="MailScope AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# Helpers
# ============================================================

def backend_status() -> dict[str, Any]:
    try:
        response = requests.get(
            f"{API_BASE_URL}/openapi.json",
            timeout=5,
        )

        response.raise_for_status()

        payload = response.json()

        paths = payload.get(
            "paths",
            {},
        )

        return {
            "online": True,
            "routes": len(
                paths
            ),
            "error": None,
        }

    except Exception as error:
        return {
            "online": False,
            "routes": 0,
            "error": str(
                error
            ),
        }


def benchmark_status() -> dict[str, Any]:
    if not BENCHMARK_REPORT.exists():
        return {}

    try:
        return json.loads(
            BENCHMARK_REPORT.read_text(
                encoding="utf-8"
            )
        )

    except Exception:
        return {}


def request_investigation(
    url: str,
) -> dict[str, Any]:
    response = requests.get(
        (
            f"{API_BASE_URL}"
            "/analyst/investigation/url"
        ),

        params={
            "url": url,
        },

        timeout=120,
    )

    response.raise_for_status()

    payload = response.json()

    if not isinstance(
        payload,
        dict,
    ):
        raise RuntimeError(
            "Backend returned an invalid "
            "investigation response."
        )

    return payload


def safe_artifact_bytes(
    path_string: str | None,
) -> bytes | None:
    if not path_string:
        return None

    try:
        path = Path(
            path_string
        )

        if not path.is_absolute():
            path = (
                PROJECT_ROOT
                / path
            )

        path = path.resolve()

        # Prevent arbitrary file reads.
        allowed_root = (
            PROJECT_ROOT
            / "data"
            / "investigations"
        ).resolve()

        if allowed_root not in (
            path,
            *path.parents,
        ):
            return None

        if not path.exists():
            return None

        return path.read_bytes()

    except Exception:
        return None


def verdict_icon(
    verdict: str,
) -> str:
    value = str(
        verdict or ""
    ).lower()

    if value in {
        "malicious",
        "likely_phishing",
    }:
        return "🚨"

    if value == "suspicious":
        return "⚠️"

    if value == "benign":
        return "✅"

    return "🔎"


def verdict_label(
    verdict: str,
) -> str:
    return (
        str(
            verdict
            or "unknown"
        )
        .replace(
            "_",
            " ",
        )
        .upper()
    )


# ============================================================
# Sidebar
# ============================================================

with st.sidebar:
    st.title(
        "🛡️ Security Console"
    )

    st.caption(
        "AI-assisted phishing investigation"
    )

    st.divider()

    st.markdown(
        "**Core Engine**  \n"
        "v1.0 · Frozen"
    )

    st.markdown(
        "**AI Analyst**  \n"
        "Mock provider · Free development mode"
    )

    st.markdown(
        "**Grounding**  \n"
        "Evidence citations required"
    )

    st.divider()

    st.caption(
        "AI interprets deterministic evidence. "
        "It does not create security facts."
    )


# ============================================================
# Platform status
# ============================================================

status = backend_status()
benchmark = benchmark_status()


st.title(
    "🛡️ MailScope AI"
)

st.caption(
    "Evidence-grounded phishing investigation and "
    "AI-assisted security analysis."
)


column1, column2, column3, column4 = (
    st.columns(
        4
    )
)


column1.metric(
    "Backend",
    (
        "ONLINE"
        if status[
            "online"
        ]
        else "OFFLINE"
    ),
)


column2.metric(
    "API Routes",
    status[
        "routes"
    ],
)


column3.metric(
    "Core Engine",
    "v1.0",
)


column4.metric(
    "AI Provider",
    "MOCK · FREE",
)


if not status[
    "online"
]:
    st.error(
        "FastAPI is currently unavailable."
    )

    st.code(
        status[
            "error"
        ]
        or "Unknown backend error"
    )


# ============================================================
# Campaign Intelligence API
# ============================================================

def request_campaigns_for_investigation(
    investigation_id: str,
) -> dict:
    """
    Read deterministic campaign relationships for an
    investigation.

    This lookup does not create campaigns, rerun detection,
    invoke AI, or modify the investigation verdict.
    """

    response = requests.get(
        (
            API_BASE_URL
            + "/campaigns/investigation/"
            + investigation_id
        ),
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# Threat Hunting API
# ============================================================

def request_threat_hunt(
    query: str,
    observable_type: str | None = None,
) -> dict:
    params = {
        "query": query,
    }

    if observable_type:
        params["observable_type"] = observable_type

    response = requests.get(
        API_BASE_URL + "/threat-hunts/search",
        params=params,
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# Case Management + Threat Graph API
# ============================================================

def request_cases() -> dict:
    response = requests.get(
        API_BASE_URL + "/cases",
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def request_create_case(
    title: str,
    priority: str,
    investigation_id: str,
) -> dict:
    response = requests.post(
        API_BASE_URL + "/cases",
        json={
            "title": title,
            "priority": priority,
            "investigation_ids": [
                investigation_id
            ],
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def request_update_case(
    case_id: str,
    status: str,
    priority: str,
) -> dict:
    response = requests.patch(
        API_BASE_URL + "/cases/" + case_id,
        json={
            "status": status,
            "priority": priority,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def request_attach_case_investigation(
    case_id: str,
    investigation_id: str,
) -> dict:
    response = requests.post(
        (
            API_BASE_URL
            + "/cases/"
            + case_id
            + "/investigations"
        ),
        json={
            "investigation_id": investigation_id,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def request_add_case_note(
    case_id: str,
    note: str,
) -> dict:
    response = requests.post(
        (
            API_BASE_URL
            + "/cases/"
            + case_id
            + "/notes"
        ),
        json={
            "note": note,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def request_threat_graph(
    investigation_id: str,
) -> dict:
    response = requests.get(
        (
            API_BASE_URL
            + "/threat-graph/investigation/"
            + investigation_id
        ),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def graphviz_escape(value) -> str:
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    return value


# ============================================================
# SOC Copilot API
# ============================================================

def request_soc_copilot(
    investigation_id: str,
    question: str,
) -> dict:
    response = requests.post(
        (
            API_BASE_URL
            + "/soc-copilot/investigation/"
            + investigation_id
            + "/ask"
        ),
        json={
            "question": question,
        },
        timeout=20,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# SOC Investigation Workspace — Version 1.5
# ============================================================

st.divider()

st.header(
    "🛡️ SOC Investigation Workspace"
)

st.caption(
    "Evidence-grounded investigation powered by the frozen "
    "Core Engine, organizational identity intelligence, "
    "grounded AI analysis, and the canonical report engine."
)


# ============================================================
# Investigation target
# ============================================================

default_url = (
    "https://microsoft-login.pages.dev/"
)

url = st.text_input(
    "Investigation target",
    value=default_url,
    placeholder="https://example.com/",
)

analyze_clicked = st.button(
    "🔎 Start Investigation",
    type="primary",
    use_container_width=True,
)


if analyze_clicked:
    if not status["online"]:
        st.error(
            "Start the FastAPI backend before "
            "running an investigation."
        )

    elif not url.strip():
        st.warning(
            "Enter a URL."
        )

    else:
        progress = st.progress(
            0,
            text="Initializing investigation...",
        )

        try:
            progress.progress(
                10,
                text="Preparing investigation target...",
            )

            progress.progress(
                25,
                text="Running Core Engine analysis...",
            )

            progress.progress(
                40,
                text="Resolving organizational identity...",
            )

            progress.progress(
                55,
                text="Building deterministic evidence...",
            )

            progress.progress(
                70,
                text="Running grounded analyst assessment...",
            )

            payload = request_investigation(
                url.strip()
            )

            progress.progress(
                90,
                text="Generating investigation artifacts...",
            )

            st.session_state[
                "latest_investigation"
            ] = payload

            progress.progress(
                100,
                text="Investigation complete.",
            )

        except Exception as error:
            st.error(
                "Investigation failed."
            )

            st.exception(
                error
            )


payload = st.session_state.get(
    "latest_investigation"
)


if payload:
    report = payload.get(
        "report",
        {},
    )

    artifacts = payload.get(
        "artifacts",
        {},
    )

    verdict = str(
        report.get(
            "verdict",
            "unknown",
        )
    )

    confidence = float(
        report.get(
            "confidence",
            0.0,
        )
        or 0.0
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
    ).upper()

    investigation_id = str(
        report.get(
            "investigation_id",
            "unknown",
        )
    )

    target = str(
        report.get(
            "target",
            "unknown",
        )
    )

    created_at = str(
        report.get(
            "created_at",
            "unknown",
        )
    )

    analyst_model = str(
        report.get(
            "analyst_model",
            "unknown",
        )
    )

    metadata = report.get(
        "metadata",
        {},
    ) or {}

    findings = report.get(
        "findings",
        [],
    ) or []

    identity = report.get(
        "identity",
        {},
    ) or {}

    iocs = report.get(
        "iocs",
        [],
    ) or []

    mitre = report.get(
        "mitre_attack",
        [],
    ) or []

    timeline = report.get(
        "timeline",
        [],
    ) or []

    recommendations = report.get(
        "recommendations",
        [],
    ) or []

    limitations = report.get(
        "limitations",
        [],
    ) or []

    evidence = report.get(
        "evidence",
        {},
    ) or {}


    # ========================================================
    # Campaign Intelligence lookup
    # ========================================================

    campaign_payload = {
        "count": 0,
        "campaigns": [],
    }

    campaign_lookup_error = None

    if (
        investigation_id
        and investigation_id != "unknown"
    ):
        try:
            campaign_payload = (
                request_campaigns_for_investigation(
                    investigation_id
                )
            )

        except Exception as error:
            campaign_lookup_error = str(
                error
            )

    campaigns = campaign_payload.get(
        "campaigns",
        [],
    ) or []


    # ========================================================
    # Case header
    # ========================================================

    st.divider()

    header_left, header_right = st.columns(
        [4, 1]
    )

    with header_left:
        st.subheader(
            verdict_icon(verdict)
            + " "
            + verdict_label(verdict)
        )

        st.markdown(
            f"**{target}**"
        )

        st.caption(
            f"Investigation ID: {investigation_id}"
        )

    with header_right:
        st.success(
            "● COMPLETE"
        )


    # ========================================================
    # Primary SOC metrics
    # ========================================================

    metric1, metric2, metric3, metric4 = (
        st.columns(4)
    )

    metric1.metric(
        "Verdict",
        verdict_label(verdict),
    )

    metric2.metric(
        "Confidence",
        f"{confidence:.0f}%",
    )

    metric3.metric(
        "Core Severity",
        f"{severity:.1f}/10",
    )

    metric4.metric(
        "Risk Level",
        risk_level,
    )


    # ========================================================
    # Risk visualization
    # ========================================================

    st.markdown(
        "### Risk Assessment"
    )

    normalized_risk = max(
        0.0,
        min(
            severity / 10.0,
            1.0,
        ),
    )

    st.progress(
        normalized_risk,
        text=(
            f"{risk_level} · "
            f"{severity:.1f}/10"
        ),
    )

    st.caption(
        "Risk severity is produced by the deterministic "
        "Core Engine. AI confidence is displayed separately "
        "and does not replace the Core Engine score."
    )


    # ========================================================
    # Investigation pipeline
    # ========================================================

    st.markdown(
        "### Investigation Pipeline"
    )

    (
        stage1,
        stage2,
        stage3,
        stage4,
        stage5,
    ) = st.columns(5)

    stage1.success(
        "✓ Evidence"
    )

    stage2.success(
        "✓ Core Analysis"
    )

    stage3.success(
        "✓ Identity"
    )

    stage4.success(
        "✓ AI Assessment"
    )

    stage5.success(
        "✓ Report"
    )


    # ========================================================
    # Executive assessment
    # ========================================================

    st.markdown(
        "### Executive Assessment"
    )

    st.info(
        report.get(
            "executive_summary",
            "No executive summary available.",
        )
    )


    # ========================================================
    # Investigation summary
    # ========================================================

    st.markdown(
        "### Investigation Summary"
    )

    summary1, summary2, summary3, summary4 = (
        st.columns(4)
    )

    summary1.metric(
        "Findings",
        len(findings),
    )

    summary2.metric(
        "Indicators",
        len(iocs),
    )

    summary3.metric(
        "MITRE Techniques",
        len(mitre),
    )

    summary4.metric(
        "Timeline Events",
        len(timeline),
    )


    # ========================================================
    # Investigation tabs
    # ========================================================

    (
        findings_tab,
        evidence_tab,
        identity_tab,
        ioc_tab,
        campaign_tab,
        case_tab,
        graph_tab,
        copilot_tab,
        mitre_tab,
        timeline_tab,
        actions_tab,
    ) = st.tabs(
        [
            "🔎 Findings",
            "📚 Evidence",
            "🏢 Identity",
            "🎯 IOCs",
            "🕸️ Campaign",
            "📁 Case",
            "🕸️ Threat Graph",
            "🤖 SOC Copilot",
            "🧭 MITRE ATT&CK",
            "🕒 Timeline",
            "🛡️ Actions",
        ]
    )


    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    with findings_tab:
        if not findings:
            st.info(
                "No analyst findings."
            )

        for index, finding in enumerate(
            findings,
            start=1,
        ):
            finding_severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()

            with st.container(
                border=True
            ):
                title_col, severity_col = (
                    st.columns(
                        [4, 1]
                    )
                )

                with title_col:
                    st.markdown(
                        f"### {index}. "
                        + str(
                            finding.get(
                                "title",
                                "Finding",
                            )
                        )
                    )

                with severity_col:
                    st.metric(
                        "Severity",
                        finding_severity,
                    )

                st.write(
                    finding.get(
                        "explanation",
                        "",
                    )
                )

                evidence_ids = finding.get(
                    "evidence_ids",
                    [],
                )

                if evidence_ids:
                    st.caption(
                        "Evidence references: "
                        + ", ".join(
                            evidence_ids
                        )
                    )


    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    with evidence_tab:
        evidence_findings = evidence.get(
            "findings",
            [],
        ) or []

        ev1, ev2, ev3 = st.columns(
            3
        )

        ev1.metric(
            "Evidence Findings",
            len(
                evidence_findings
            ),
        )

        ev2.metric(
            "Evidence Grounded",
            (
                "YES"
                if evidence.get(
                    "metadata",
                    {}
                ).get(
                    "evidence_grounded"
                )
                else "NO"
            ),
        )

        ev3.metric(
            "AI Used For Evidence",
            (
                "YES"
                if evidence.get(
                    "metadata",
                    {}
                ).get(
                    "ai_used_for_evidence"
                )
                else "NO"
            ),
        )

        if evidence_findings:
            st.markdown(
                "#### Evidence Observations"
            )

            for index, item in enumerate(
                evidence_findings,
                start=1,
            ):
                with st.container(
                    border=True
                ):
                    st.markdown(
                        f"**E{index} · "
                        + str(
                            item.get(
                                "title",
                                "Evidence",
                            )
                        )
                        + "**"
                    )

                    st.write(
                        item.get(
                            "description",
                            "",
                        )
                    )

                    st.caption(
                        "Source: "
                        + str(
                            item.get(
                                "source",
                                "unknown",
                            )
                        )
                        + " · Category: "
                        + str(
                            item.get(
                                "category",
                                "unknown",
                            )
                        )
                    )

        with st.expander(
            "Raw Evidence Package"
        ):
            st.json(
                evidence
            )


    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    with identity_tab:
        i1, i2, i3 = st.columns(
            3
        )

        i1.metric(
            "Identity State",
            str(
                identity.get(
                    "state",
                    "unknown",
                )
            ).upper(),
        )

        i2.metric(
            "Identity Confidence",
            (
                f"{float(identity.get('confidence', 0) or 0):.0f}%"
            ),
        )

        i3.metric(
            "Known Identity",
            (
                "YES"
                if identity.get(
                    "known"
                )
                else "NO"
            ),
        )

        with st.container(
            border=True
        ):
            st.markdown(
                "#### Organization"
            )

            st.write(
                identity.get(
                    "organization"
                )
                or "Unknown"
            )

            st.markdown(
                "#### Canonical Domain"
            )

            st.code(
                identity.get(
                    "canonical_domain"
                )
                or "Unknown"
            )

            sources = identity.get(
                "sources",
                [],
            )

            if sources:
                st.markdown(
                    "#### Identity Sources"
                )

                st.write(
                    " · ".join(
                        str(source)
                        for source in sources
                    )
                )


    # --------------------------------------------------------
    # IOCs
    # --------------------------------------------------------

    with ioc_tab:
        if not iocs:
            st.info(
                "No indicators or observables "
                "were extracted."
            )

        else:
            st.caption(
                f"{len(iocs)} indicators extracted "
                "from the investigation."
            )

            st.dataframe(
                iocs,
                use_container_width=True,
                hide_index=True,
            )


    # --------------------------------------------------------
    # Campaign Intelligence
    # --------------------------------------------------------

    with campaign_tab:
        st.markdown(
            "### Campaign Intelligence"
        )

        st.caption(
            "Deterministic cross-investigation correlation "
            "using evidence-backed observables."
        )

        if campaign_lookup_error:
            st.warning(
                "Campaign history is currently unavailable. "
                "The investigation itself remains valid."
            )

            with st.expander(
                "Campaign lookup details"
            ):
                st.code(
                    campaign_lookup_error
                )

        elif not campaigns:
            st.info(
                "No related campaign candidate is currently "
                "associated with this investigation."
            )

            st.caption(
                "An isolated investigation is not evidence "
                "of safety or maliciousness. It only means "
                "the campaign correlation store currently "
                "contains no qualifying relationship."
            )

        else:
            st.success(
                (
                    str(len(campaigns))
                    + " campaign candidate"
                    + (
                        ""
                        if len(campaigns) == 1
                        else "s"
                    )
                    + " associated with this investigation."
                )
            )

            for campaign_index, campaign in enumerate(
                campaigns,
                start=1,
            ):
                campaign_id = str(
                    campaign.get(
                        "campaign_id",
                        "unknown",
                    )
                )

                campaign_score = float(
                    campaign.get(
                        "correlation_score",
                        0.0,
                    )
                    or 0.0
                )

                campaign_strength = str(
                    campaign.get(
                        "strength",
                        "unknown",
                    )
                ).upper()

                investigation_ids = (
                    campaign.get(
                        "investigation_ids",
                        [],
                    )
                    or []
                )

                relationships = (
                    campaign.get(
                        "relationships",
                        [],
                    )
                    or []
                )

                shared_artifacts = (
                    campaign.get(
                        "shared_artifacts",
                        [],
                    )
                    or []
                )

                campaign_metadata = (
                    campaign.get(
                        "metadata",
                        {},
                    )
                    or {}
                )

                with st.container(
                    border=True
                ):
                    st.markdown(
                        "#### Campaign Candidate "
                        + str(
                            campaign_index
                        )
                    )

                    st.code(
                        campaign_id
                    )

                    (
                        campaign_metric1,
                        campaign_metric2,
                        campaign_metric3,
                        campaign_metric4,
                    ) = st.columns(4)

                    campaign_metric1.metric(
                        "Strength",
                        campaign_strength,
                    )

                    campaign_metric2.metric(
                        "Correlation Score",
                        f"{campaign_score:.2f}",
                    )

                    campaign_metric3.metric(
                        "Investigations",
                        len(
                            investigation_ids
                        ),
                    )

                    campaign_metric4.metric(
                        "Shared Artifacts",
                        len(
                            shared_artifacts
                        ),
                    )

                    st.progress(
                        max(
                            0.0,
                            min(
                                campaign_score,
                                1.0,
                            ),
                        ),
                        text=(
                            campaign_strength
                            + " correlation · "
                            + f"{campaign_score:.2f}"
                        ),
                    )

                    time1, time2 = st.columns(
                        2
                    )

                    time1.metric(
                        "First Seen",
                        str(
                            campaign.get(
                                "first_seen",
                                "Unknown",
                            )
                            or "Unknown"
                        ),
                    )

                    time2.metric(
                        "Last Seen",
                        str(
                            campaign.get(
                                "last_seen",
                                "Unknown",
                            )
                            or "Unknown"
                        ),
                    )

                    st.markdown(
                        "##### Related Investigations"
                    )

                    if investigation_ids:
                        for related_id in (
                            investigation_ids
                        ):
                            if (
                                str(related_id)
                                == investigation_id
                            ):
                                st.markdown(
                                    "- **"
                                    + str(
                                        related_id
                                    )
                                    + "** · current investigation"
                                )

                            else:
                                st.markdown(
                                    "- "
                                    + str(
                                        related_id
                                    )
                                )

                    else:
                        st.caption(
                            "No investigation identifiers "
                            "are available."
                        )

                    st.markdown(
                        "##### Shared Observables"
                    )

                    if shared_artifacts:
                        artifact_rows = [
                            {
                                "Type": artifact.get(
                                    "type",
                                    "unknown",
                                ),
                                "Value": artifact.get(
                                    "value",
                                    "",
                                ),
                                "Source": artifact.get(
                                    "source",
                                    "unknown",
                                ),
                                "Confidence": artifact.get(
                                    "confidence",
                                ),
                            }
                            for artifact
                            in shared_artifacts
                        ]

                        st.dataframe(
                            artifact_rows,
                            use_container_width=True,
                            hide_index=True,
                        )

                    else:
                        st.caption(
                            "No shared artifact details "
                            "are available."
                        )

                    st.markdown(
                        "##### Evidence-backed Relationships"
                    )

                    if relationships:
                        for relationship_index, relationship in enumerate(
                            relationships,
                            start=1,
                        ):
                            relationship_strength = float(
                                relationship.get(
                                    "strength",
                                    0.0,
                                )
                                or 0.0
                            )

                            with st.expander(
                                (
                                    "Relationship "
                                    + str(
                                        relationship_index
                                    )
                                    + " · "
                                    + str(
                                        relationship.get(
                                            "artifact_type",
                                            "observable",
                                        )
                                    ).upper()
                                )
                            ):
                                st.write(
                                    "**"
                                    + str(
                                        relationship.get(
                                            "investigation_a",
                                            "unknown",
                                        )
                                    )
                                    + "** ↔ **"
                                    + str(
                                        relationship.get(
                                            "investigation_b",
                                            "unknown",
                                        )
                                    )
                                    + "**"
                                )

                                st.code(
                                    str(
                                        relationship.get(
                                            "artifact_value",
                                            "",
                                        )
                                    )
                                )

                                st.metric(
                                    "Relationship Weight",
                                    f"{relationship_strength:.2f}",
                                )

                                st.write(
                                    relationship.get(
                                        "rationale",
                                        (
                                            "Shared evidence-backed "
                                            "observable."
                                        ),
                                    )
                                )

                    else:
                        st.caption(
                            "No relationship details "
                            "are available."
                        )

                    st.markdown(
                        "##### Campaign Timeline"
                    )

                    campaign_events = []

                    for related_id in (
                        investigation_ids
                    ):
                        if (
                            str(related_id)
                            == investigation_id
                        ):
                            campaign_events.append(
                                {
                                    "Investigation": (
                                        str(
                                            related_id
                                        )
                                    ),
                                    "Observed": (
                                        created_at
                                    ),
                                    "Context": (
                                        "Current investigation"
                                    ),
                                }
                            )

                    if campaign_events:
                        st.dataframe(
                            campaign_events,
                            use_container_width=True,
                            hide_index=True,
                        )

                    st.caption(
                        "The campaign record currently stores "
                        "first/last-seen bounds and relationship "
                        "evidence. Full historical investigation "
                        "timestamps remain available through "
                        "their canonical reports."
                    )

                    with st.expander(
                        "Correlation Trust Boundary"
                    ):
                        st.markdown(
                            """
- Campaign grouping is deterministic.
- Correlation does **not** change the phishing verdict.
- A shared observable does **not** prove maliciousness.
- Shared hosting or shared IP infrastructure alone is not sufficient campaign evidence.
- Campaign membership does **not** establish common threat-actor attribution.
- No AI is used to decide campaign membership.
- No external lookup is performed by the correlation engine.
- No new threat facts are generated during correlation.
                            """
                        )

                        boundary1, boundary2, boundary3 = (
                            st.columns(3)
                        )

                        boundary1.metric(
                            "Deterministic",
                            (
                                "YES"
                                if campaign_metadata.get(
                                    "deterministic"
                                )
                                else "NO"
                            ),
                        )

                        boundary2.metric(
                            "AI Used",
                            (
                                "YES"
                                if campaign_metadata.get(
                                    "ai_used"
                                )
                                else "NO"
                            ),
                        )

                        boundary3.metric(
                            "Threat Actor Attributed",
                            (
                                "YES"
                                if campaign_metadata.get(
                                    "threat_actor_attributed"
                                )
                                else "NO"
                            ),
                        )


    # --------------------------------------------------------
    # Case Management
    # --------------------------------------------------------

    with case_tab:
        st.markdown(
            "### 📁 Case Management"
        )

        st.caption(
            "Create and manage analyst cases without changing "
            "the underlying investigation verdict."
        )

        try:
            cases_payload = request_cases()

            available_cases = (
                cases_payload.get(
                    "cases",
                    [],
                )
                or []
            )

        except Exception as error:
            available_cases = []

            st.warning(
                "Case history is currently unavailable."
            )

            with st.expander(
                "Case API details"
            ):
                st.code(
                    str(error)
                )

        attached_cases = [
            case
            for case in available_cases
            if investigation_id
            in (
                case.get(
                    "investigation_ids",
                    [],
                )
                or []
            )
        ]

        c1, c2 = st.columns(2)

        c1.metric(
            "Cases",
            len(available_cases),
        )

        c2.metric(
            "Attached To Investigation",
            len(attached_cases),
        )

        st.markdown(
            "#### Create Case"
        )

        with st.form(
            "create_case_"
            + investigation_id
        ):
            new_case_title = (
                st.text_input(
                    "Case Title",
                    value=(
                        "Investigation "
                        + investigation_id
                    ),
                )
            )

            new_case_priority = (
                st.selectbox(
                    "Priority",
                    [
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                    index=1,
                )
            )

            create_case_clicked = (
                st.form_submit_button(
                    "Create Case + Attach Investigation",
                    type="primary",
                    use_container_width=True,
                )
            )

        if create_case_clicked:
            if not new_case_title.strip():
                st.warning(
                    "Enter a case title."
                )

            else:
                try:
                    created_case = (
                        request_create_case(
                            new_case_title.strip(),
                            new_case_priority,
                            investigation_id,
                        )
                    )

                    st.session_state[
                        "workspace_case_id"
                    ] = created_case.get(
                        "case_id"
                    )

                    st.success(
                        "Case created: "
                        + str(
                            created_case.get(
                                "case_id",
                                "",
                            )
                        )
                    )

                    st.rerun()

                except Exception as error:
                    st.error(
                        "Case creation failed."
                    )

                    st.exception(
                        error
                    )

        if available_cases:
            st.divider()

            st.markdown(
                "#### Analyst Case Workspace"
            )

            case_lookup = {
                (
                    str(
                        case.get(
                            "case_id",
                            "unknown",
                        )
                    )
                    + " · "
                    + str(
                        case.get(
                            "title",
                            "Untitled",
                        )
                    )
                ): case
                for case
                in available_cases
            }

            case_labels = list(
                case_lookup.keys()
            )

            selected_label = (
                st.selectbox(
                    "Select Case",
                    case_labels,
                    key=(
                        "workspace_case_selector"
                    ),
                )
            )

            selected_case = (
                case_lookup[
                    selected_label
                ]
            )

            selected_case_id = str(
                selected_case.get(
                    "case_id",
                    ""
                )
            )

            case_status = str(
                selected_case.get(
                    "status",
                    "open",
                )
            ).lower()

            case_priority = str(
                selected_case.get(
                    "priority",
                    "medium",
                )
            ).lower()

            status_options = [
                "open",
                "investigating",
                "contained",
                "closed",
            ]

            priority_options = [
                "low",
                "medium",
                "high",
                "critical",
            ]

            if (
                case_status
                not in status_options
            ):
                case_status = "open"

            if (
                case_priority
                not in priority_options
            ):
                case_priority = "medium"

            cm1, cm2, cm3 = (
                st.columns(3)
            )

            cm1.metric(
                "Case ID",
                selected_case_id,
            )

            cm2.metric(
                "Status",
                case_status.upper(),
            )

            cm3.metric(
                "Priority",
                case_priority.upper(),
            )

            attached_ids = (
                selected_case.get(
                    "investigation_ids",
                    [],
                )
                or []
            )

            if (
                investigation_id
                in attached_ids
            ):
                st.success(
                    "Current investigation is attached "
                    "to this case."
                )

            else:
                if st.button(
                    "Attach Current Investigation",
                    key=(
                        "attach_"
                        + selected_case_id
                    ),
                    use_container_width=True,
                ):
                    try:
                        request_attach_case_investigation(
                            selected_case_id,
                            investigation_id,
                        )

                        st.success(
                            "Investigation attached."
                        )

                        st.rerun()

                    except Exception as error:
                        st.error(
                            "Could not attach investigation."
                        )

                        st.exception(
                            error
                        )

            with st.form(
                "update_case_"
                + selected_case_id
            ):
                u1, u2 = st.columns(2)

                with u1:
                    updated_status = (
                        st.selectbox(
                            "Case Status",
                            status_options,
                            index=(
                                status_options.index(
                                    case_status
                                )
                            ),
                        )
                    )

                with u2:
                    updated_priority = (
                        st.selectbox(
                            "Case Priority",
                            priority_options,
                            index=(
                                priority_options.index(
                                    case_priority
                                )
                            ),
                        )
                    )

                update_clicked = (
                    st.form_submit_button(
                        "Update Case",
                        use_container_width=True,
                    )
                )

            if update_clicked:
                try:
                    request_update_case(
                        selected_case_id,
                        updated_status,
                        updated_priority,
                    )

                    st.success(
                        "Case updated."
                    )

                    st.rerun()

                except Exception as error:
                    st.error(
                        "Case update failed."
                    )

                    st.exception(
                        error
                    )

            st.markdown(
                "##### Attached Investigations"
            )

            if attached_ids:
                for attached_id in (
                    attached_ids
                ):
                    st.code(
                        str(
                            attached_id
                        )
                    )

            else:
                st.caption(
                    "No investigations attached."
                )

            st.markdown(
                "##### Analyst Notes"
            )

            notes = (
                selected_case.get(
                    "notes",
                    [],
                )
                or []
            )

            if notes:
                for note in reversed(
                    notes
                ):
                    with st.container(
                        border=True
                    ):
                        st.write(
                            note.get(
                                "text",
                                "",
                            )
                        )

                        st.caption(
                            str(
                                note.get(
                                    "created_at",
                                    "",
                                )
                            )
                        )

            else:
                st.caption(
                    "No analyst notes yet."
                )

            with st.form(
                "case_note_"
                + selected_case_id
            ):
                note_text = (
                    st.text_area(
                        "Add Analyst Note",
                        placeholder=(
                            "Record investigation context, "
                            "triage decisions, escalation..."
                        ),
                    )
                )

                note_clicked = (
                    st.form_submit_button(
                        "Add Note",
                        use_container_width=True,
                    )
                )

            if note_clicked:
                if not note_text.strip():
                    st.warning(
                        "Enter a note."
                    )

                else:
                    try:
                        request_add_case_note(
                            selected_case_id,
                            note_text.strip(),
                        )

                        st.success(
                            "Analyst note added."
                        )

                        st.rerun()

                    except Exception as error:
                        st.error(
                            "Could not add analyst note."
                        )

                        st.exception(
                            error
                        )

        else:
            st.info(
                "No analyst cases exist yet."
            )

        with st.expander(
            "🔐 Case Management Trust Boundary"
        ):
            st.markdown(
                """
- Cases organize analyst workflow; they do not change detection results.
- Historical investigation verdicts remain immutable through case actions.
- Analyst notes are explicitly human-authored.
- Case priority and status are workflow metadata, not phishing evidence.
- Attaching investigations does not imply common threat-actor attribution.
                """
            )


    # --------------------------------------------------------
    # Threat Graph
    # --------------------------------------------------------

    with graph_tab:
        st.markdown(
            "### 🕸️ Threat Graph"
        )

        st.caption(
            "Evidence-backed relationship graph derived from "
            "the canonical investigation report."
        )

        try:
            threat_graph = (
                request_threat_graph(
                    investigation_id
                )
            )

            graph_nodes = (
                threat_graph.get(
                    "nodes",
                    [],
                )
                or []
            )

            graph_edges = (
                threat_graph.get(
                    "edges",
                    [],
                )
                or []
            )

            graph_metadata = (
                threat_graph.get(
                    "metadata",
                    {},
                )
                or {}
            )

            g1, g2, g3 = (
                st.columns(3)
            )

            g1.metric(
                "Nodes",
                len(graph_nodes),
            )

            g2.metric(
                "Relationships",
                len(graph_edges),
            )

            g3.metric(
                "Evidence Backed",
                (
                    "YES"
                    if graph_metadata.get(
                        "evidence_backed"
                    )
                    else "NO"
                ),
            )

            dot_lines = [
                "digraph ThreatGraph {",
                'rankdir="LR";',
                'graph [pad="0.3", nodesep="0.6", ranksep="0.8"];',
                'node [shape="box", style="rounded"];',
            ]

            for node in graph_nodes:
                node_id = graphviz_escape(
                    node.get(
                        "node_id",
                        "",
                    )
                )

                node_type = str(
                    node.get(
                        "node_type",
                        "observable",
                    )
                ).upper()

                node_value = str(
                    node.get(
                        "label",
                        node.get(
                            "value",
                            "",
                        ),
                    )
                )

                if len(node_value) > 55:
                    node_value = (
                        node_value[:52]
                        + "..."
                    )

                label = graphviz_escape(
                    node_type
                    + "\n"
                    + node_value
                )

                dot_lines.append(
                    '"'
                    + node_id
                    + '" [label="'
                    + label
                    + '"];'
                )

            for edge in graph_edges:
                source = graphviz_escape(
                    edge.get(
                        "source",
                        "",
                    )
                )

                target_node_id = (
                    graphviz_escape(
                        edge.get(
                            "target",
                            "",
                        )
                    )
                )

                relationship = (
                    graphviz_escape(
                        str(
                            edge.get(
                                "relationship",
                                "related",
                            )
                        ).replace(
                            "_",
                            " ",
                        )
                    )
                )

                dot_lines.append(
                    '"'
                    + source
                    + '" -> "'
                    + target_node_id
                    + '" [label="'
                    + relationship
                    + '"];'
                )

            dot_lines.append(
                "}"
            )

            dot_graph = "\n".join(
                dot_lines
            )

            if graph_nodes:
                st.graphviz_chart(
                    dot_graph
                )

            else:
                st.info(
                    "No graph nodes were generated."
                )

            st.markdown(
                "#### Evidence Relationships"
            )

            if graph_edges:
                relationship_rows = []

                node_lookup = {
                    node.get(
                        "node_id"
                    ): node
                    for node
                    in graph_nodes
                }

                for edge in graph_edges:
                    source_node = (
                        node_lookup.get(
                            edge.get(
                                "source"
                            ),
                            {},
                        )
                    )

                    target_node = (
                        node_lookup.get(
                            edge.get(
                                "target"
                            ),
                            {},
                        )
                    )

                    relationship_rows.append(
                        {
                            "Source": (
                                source_node.get(
                                    "value",
                                    edge.get(
                                        "source",
                                        "",
                                    ),
                                )
                            ),
                            "Relationship": (
                                str(
                                    edge.get(
                                        "relationship",
                                        "",
                                    )
                                ).replace(
                                    "_",
                                    " ",
                                )
                            ),
                            "Target": (
                                target_node.get(
                                    "value",
                                    edge.get(
                                        "target",
                                        "",
                                    ),
                                )
                            ),
                            "Evidence": (
                                edge.get(
                                    "evidence_source",
                                    "",
                                )
                            ),
                        }
                    )

                st.dataframe(
                    relationship_rows,
                    use_container_width=True,
                    hide_index=True,
                )

            with st.expander(
                "🔐 Threat Graph Trust Boundary"
            ):
                st.markdown(
                    """
- Graph relationships come from canonical report evidence.
- No AI creates or infers graph relationships.
- No external lookup occurs while constructing the graph.
- The graph does not attribute activity to a threat actor.
- Identity context is displayed as context, not proof of maliciousness.
- A visual connection represents recorded evidence, not automatic causation.
                    """
                )

                tg1, tg2, tg3 = (
                    st.columns(3)
                )

                tg1.metric(
                    "Deterministic",
                    (
                        "YES"
                        if graph_metadata.get(
                            "deterministic"
                        )
                        else "NO"
                    ),
                )

                tg2.metric(
                    "AI Used",
                    (
                        "YES"
                        if graph_metadata.get(
                            "ai_used"
                        )
                        else "NO"
                    ),
                )

                tg3.metric(
                    "Threat Actor Attributed",
                    (
                        "YES"
                        if graph_metadata.get(
                            "threat_actor_attributed"
                        )
                        else "NO"
                    ),
                )

        except Exception as error:
            st.warning(
                "Threat Graph is currently unavailable "
                "for this investigation."
            )

            with st.expander(
                "Threat Graph API details"
            ):
                st.code(
                    str(error)
                )


    # --------------------------------------------------------
    # SOC Copilot
    # --------------------------------------------------------

    with copilot_tab:
        st.markdown(
            "### 🤖 SOC Copilot"
        )

        st.caption(
            "Evidence-grounded investigation assistant. "
            "Copilot explains existing security evidence; "
            "it does not override the deterministic engine."
        )

        st.info(
            "Ask about the verdict, evidence, indicators, "
            "related activity, response actions, escalation, "
            "or defensive detection guidance."
        )

        st.markdown(
            "#### Quick Analyst Questions"
        )

        quick_questions = [
            "Why is this phishing?",
            "Explain E1",
            "What indicators are present?",
            "Find related investigations",
            "What should the analyst do next?",
            "Summarize for escalation",
            "Generate detection guidance",
        ]

        q1, q2 = st.columns(2)

        selected_quick_question = None

        for index, question in enumerate(
            quick_questions
        ):
            target_column = (
                q1
                if index % 2 == 0
                else q2
            )

            with target_column:
                if st.button(
                    question,
                    key=(
                        "copilot_quick_"
                        + investigation_id
                        + "_"
                        + str(index)
                    ),
                    use_container_width=True,
                ):
                    selected_quick_question = (
                        question
                    )

        st.divider()

        with st.form(
            "soc_copilot_form_"
            + investigation_id
        ):
            custom_question = (
                st.text_area(
                    "Ask SOC Copilot",
                    placeholder=(
                        "Example: Explain why this investigation "
                        "was classified as phishing."
                    ),
                    height=100,
                )
            )

            ask_clicked = (
                st.form_submit_button(
                    "Ask Copilot",
                    type="primary",
                    use_container_width=True,
                )
            )

        question_to_ask = None

        if selected_quick_question:
            question_to_ask = (
                selected_quick_question
            )

        elif ask_clicked:
            if custom_question.strip():
                question_to_ask = (
                    custom_question.strip()
                )

            else:
                st.warning(
                    "Enter a question for SOC Copilot."
                )

        if question_to_ask:
            try:
                with st.spinner(
                    "Reviewing investigation evidence..."
                ):
                    copilot_response = (
                        request_soc_copilot(
                            investigation_id,
                            question_to_ask,
                        )
                    )

                st.session_state[
                    "soc_copilot_response_"
                    + investigation_id
                ] = copilot_response

            except Exception as error:
                st.error(
                    "SOC Copilot request failed."
                )

                with st.expander(
                    "Copilot API details"
                ):
                    st.code(
                        str(error)
                    )

        copilot_response = (
            st.session_state.get(
                "soc_copilot_response_"
                + investigation_id
            )
        )

        if copilot_response:
            st.divider()

            st.markdown(
                "#### Copilot Response"
            )

            st.caption(
                "Question: "
                + str(
                    copilot_response.get(
                        "question",
                        "",
                    )
                )
            )

            st.markdown(
                str(
                    copilot_response.get(
                        "answer",
                        "No answer returned.",
                    )
                )
            )

            evidence_ids = (
                copilot_response.get(
                    "evidence_ids",
                    [],
                )
                or []
            )

            related_investigations = (
                copilot_response.get(
                    "related_investigations",
                    [],
                )
                or []
            )

            response_metadata = (
                copilot_response.get(
                    "metadata",
                    {},
                )
                or {}
            )

            r1, r2, r3 = st.columns(3)

            r1.metric(
                "Intent",
                str(
                    copilot_response.get(
                        "intent",
                        "unknown",
                    )
                ).replace(
                    "_",
                    " ",
                ).title(),
            )

            r2.metric(
                "Evidence Citations",
                len(evidence_ids),
            )

            r3.metric(
                "Grounded",
                (
                    "YES"
                    if response_metadata.get(
                        "grounded"
                    )
                    else "NO"
                ),
            )

            if evidence_ids:
                st.markdown(
                    "##### Evidence References"
                )

                st.write(
                    " · ".join(
                        evidence_ids
                    )
                )

            if related_investigations:
                st.markdown(
                    "##### Related Investigations"
                )

                for related_id in (
                    related_investigations
                ):
                    st.code(
                        str(related_id)
                    )

            if (
                copilot_response.get(
                    "intent"
                )
                == "unsupported"
            ):
                st.warning(
                    "The requested conclusion is not supported "
                    "by the available investigation evidence."
                )

            with st.expander(
                "🔐 SOC Copilot Trust Boundary"
            ):
                st.markdown(
                    """
- Copilot operates on the canonical investigation report.
- Existing evidence is assembled before Copilot interpretation.
- Unsupported evidence IDs are explicitly refused.
- Copilot cannot modify the deterministic phishing verdict.
- Copilot does not perform external threat-intelligence lookups.
- Copilot does not infer threat-actor attribution.
- Campaign relationships indicate shared evidence, not attribution.
- Defensive guidance is advisory and requires analyst validation.
                    """
                )

                t1, t2, t3, t4 = (
                    st.columns(4)
                )

                t1.metric(
                    "Grounded",
                    (
                        "YES"
                        if response_metadata.get(
                            "grounded"
                        )
                        else "NO"
                    ),
                )

                t2.metric(
                    "AI Used",
                    (
                        "YES"
                        if response_metadata.get(
                            "ai_used"
                        )
                        else "NO"
                    ),
                )

                t3.metric(
                    "External Lookup",
                    (
                        "YES"
                        if response_metadata.get(
                            "external_lookup_used"
                        )
                        else "NO"
                    ),
                )

                t4.metric(
                    "Verdict Modified",
                    (
                        "YES"
                        if response_metadata.get(
                            "verdict_modified"
                        )
                        else "NO"
                    ),
                )


    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    with mitre_tab:
        if not mitre:
            st.info(
                "No MITRE ATT&CK techniques "
                "were assigned."
            )

        for item in mitre:
            with st.container(
                border=True
            ):
                technique_id = str(
                    item.get(
                        "technique_id",
                        "Unknown",
                    )
                )

                technique_name = str(
                    item.get(
                        "technique_name",
                        "Unknown",
                    )
                )

                st.markdown(
                    f"### {technique_id} — "
                    f"{technique_name}"
                )

                st.write(
                    item.get(
                        "reason",
                        "",
                    )
                )


    # --------------------------------------------------------
    # Timeline
    # --------------------------------------------------------

    with timeline_tab:
        if not timeline:
            st.info(
                "No investigation timeline "
                "is available."
            )

        for index, event in enumerate(
            timeline,
            start=1,
        ):
            with st.container(
                border=True
            ):
                st.caption(
                    f"Step {index} · "
                    + str(
                        event.get(
                            "timestamp",
                            "",
                        )
                    )
                )

                st.markdown(
                    "**"
                    + str(
                        event.get(
                            "title",
                            "Event",
                        )
                    )
                    + "**"
                )

                st.write(
                    event.get(
                        "description",
                        "",
                    )
                )

                st.caption(
                    "Source: "
                    + str(
                        event.get(
                            "source",
                            "unknown",
                        )
                    )
                    + " · Type: "
                    + str(
                        event.get(
                            "event_type",
                            "unknown",
                        )
                    )
                )


    # --------------------------------------------------------
    # Recommended actions
    # --------------------------------------------------------

    with actions_tab:
        if recommendations:
            st.markdown(
                "#### Recommended Analyst Actions"
            )

            for index, action in enumerate(
                recommendations,
                start=1,
            ):
                st.checkbox(
                    str(action),
                    value=False,
                    key=(
                        "workspace_action_"
                        + investigation_id
                        + "_"
                        + str(index)
                    ),
                )

        else:
            st.info(
                "No recommended actions."
            )

        if limitations:
            st.divider()

            st.markdown(
                "#### Investigation Limitations"
            )

            for limitation in limitations:
                st.warning(
                    str(
                        limitation
                    )
                )


    # ========================================================
    # Engine metadata
    # ========================================================

    st.divider()

    st.markdown(
        "### Investigation Metadata"
    )

    meta1, meta2, meta3, meta4 = (
        st.columns(4)
    )

    meta1.metric(
        "Core Release",
        str(
            metadata.get(
                "core_release",
                "unknown",
            )
        ),
    )

    meta2.metric(
        "Grounded AI",
        (
            "YES"
            if metadata.get(
                "grounded_ai"
            )
            else "NO"
        ),
    )

    meta3.metric(
        "Report Schema",
        str(
            metadata.get(
                "report_schema_version",
                "unknown",
            )
        ),
    )

    meta4.metric(
        "AI Security Facts",
        (
            "YES"
            if metadata.get(
                "security_facts_generated_by_ai"
            )
            else "NO"
        ),
    )

    st.caption(
        f"Created: {created_at}"
    )

    st.caption(
        f"Analyst backend: {analyst_model}"
    )


    # ========================================================
    # Artifact downloads
    # ========================================================

    st.divider()

    st.markdown(
        "### Export Investigation"
    )

    json_bytes = safe_artifact_bytes(
        artifacts.get(
            "json"
        )
    )

    markdown_bytes = safe_artifact_bytes(
        artifacts.get(
            "markdown"
        )
    )

    ioc_bytes = safe_artifact_bytes(
        artifacts.get(
            "iocs"
        )
    )

    download1, download2, download3 = (
        st.columns(3)
    )

    with download1:
        if json_bytes:
            st.download_button(
                "⬇ JSON Report",
                data=json_bytes,
                file_name=(
                    investigation_id
                    + ".json"
                ),
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.button(
                "JSON unavailable",
                disabled=True,
                use_container_width=True,
            )

    with download2:
        if markdown_bytes:
            st.download_button(
                "⬇ Markdown Report",
                data=markdown_bytes,
                file_name=(
                    investigation_id
                    + ".md"
                ),
                mime="text/markdown",
                use_container_width=True,
            )
        else:
            st.button(
                "Markdown unavailable",
                disabled=True,
                use_container_width=True,
            )

    with download3:
        if ioc_bytes:
            st.download_button(
                "⬇ IOC CSV",
                data=ioc_bytes,
                file_name=(
                    investigation_id
                    + "_iocs.csv"
                ),
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.button(
                "IOC CSV unavailable",
                disabled=True,
                use_container_width=True,
            )


    # ========================================================
    # Trust boundary
    # ========================================================

    with st.expander(
        "🔐 Investigation Trust Model"
    ):
        st.markdown(
            """
**Deterministic security boundary**

- Core severity is generated by the deterministic Core Engine.
- Identity evidence is generated by the identity intelligence layer.
- Evidence is assembled before AI interpretation.
- The analyst may interpret supplied evidence but may not invent evidence.
- AI confidence is separate from deterministic risk severity.
- Exporters consume the canonical report and do not rerun detection.
- Campaign correlation is deterministic and does not alter the investigation verdict.
- Campaign membership does not imply maliciousness or threat-actor attribution.
            """
        )

    st.caption(
        "MailScope AI · "
        "Core Engine v1.0 · "
        "Grounded AI Analyst · "
        "Evidence-backed Investigation"
    )



# ============================================================
# Threat Hunting Workspace
# ============================================================

st.divider()

st.header(
    "🎯 Threat Hunting"
)

st.caption(
    "Search historical investigation reports by IOC or observable. "
    "Hunting is deterministic, read-only, and does not modify verdicts."
)

hunt_col1, hunt_col2 = st.columns(
    [3, 1]
)

with hunt_col1:
    hunt_query = st.text_input(
        "Observable",
        placeholder=(
            "example.com, 1.2.3.4, "
            "user@example.com, URL, SHA256..."
        ),
        key="threat_hunt_query",
    )

with hunt_col2:
    hunt_type = st.selectbox(
        "Observable Type",
        [
            "Auto",
            "domain",
            "url",
            "ip",
            "email",
            "md5",
            "sha1",
            "sha256",
            "investigation_id",
        ],
        key="threat_hunt_type",
    )

hunt_clicked = st.button(
    "Run Threat Hunt",
    type="primary",
    use_container_width=True,
)

if hunt_clicked:
    if not hunt_query.strip():
        st.warning(
            "Enter an observable to hunt."
        )

    else:
        try:
            hunt_payload = request_threat_hunt(
                hunt_query.strip(),
                (
                    None
                    if hunt_type == "Auto"
                    else hunt_type
                ),
            )

            st.session_state[
                "latest_threat_hunt"
            ] = hunt_payload

        except Exception as error:
            st.error(
                "Threat hunt failed."
            )

            st.exception(
                error
            )

hunt_payload = st.session_state.get(
    "latest_threat_hunt"
)

if hunt_payload:
    matches = hunt_payload.get(
        "matches",
        [],
    ) or []

    metadata = hunt_payload.get(
        "metadata",
        {},
    ) or {}

    h1, h2, h3 = st.columns(
        3
    )

    h1.metric(
        "Matches",
        int(
            hunt_payload.get(
                "match_count",
                len(matches),
            )
            or 0
        ),
    )

    h2.metric(
        "Reports Scanned",
        int(
            hunt_payload.get(
                "scanned_reports",
                0,
            )
            or 0
        ),
    )

    h3.metric(
        "Deterministic",
        (
            "YES"
            if metadata.get(
                "deterministic"
            )
            else "NO"
        ),
    )

    if not matches:
        st.info(
            "No historical investigations matched this observable."
        )

    else:
        st.success(
            f"{len(matches)} historical match"
            + (
                ""
                if len(matches) == 1
                else "es"
            )
            + " found."
        )

        rows = []

        for match in matches:
            rows.append(
                {
                    "Investigation ID": match.get(
                        "investigation_id",
                        "",
                    ),
                    "Target": match.get(
                        "target",
                        "",
                    ),
                    "Verdict": str(
                        match.get(
                            "verdict",
                            "unknown",
                        )
                    ),
                    "Severity": float(
                        match.get(
                            "severity",
                            0.0,
                        )
                        or 0.0
                    ),
                    "Risk": str(
                        match.get(
                            "risk_level",
                            "UNKNOWN",
                        )
                    ),
                    "Type": match.get(
                        "observable_type",
                        "",
                    ),
                    "Observable": match.get(
                        "observable_value",
                        "",
                    ),
                    "Source": match.get(
                        "source",
                        "",
                    ),
                    "Created": match.get(
                        "created_at",
                        "",
                    ),
                }
            )

        st.dataframe(
            rows,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown(
            "### Related Investigation Details"
        )

        for index, match in enumerate(
            matches,
            start=1,
        ):
            with st.expander(
                (
                    str(index)
                    + ". "
                    + str(
                        match.get(
                            "investigation_id",
                            "unknown",
                        )
                    )
                )
            ):
                d1, d2, d3 = st.columns(
                    3
                )

                d1.metric(
                    "Verdict",
                    str(
                        match.get(
                            "verdict",
                            "unknown",
                        )
                    ).replace(
                        "_",
                        " ",
                    ).title(),
                )

                d2.metric(
                    "Severity",
                    (
                        f"{float(match.get('severity', 0) or 0):.1f}/10"
                    ),
                )

                d3.metric(
                    "Risk",
                    str(
                        match.get(
                            "risk_level",
                            "UNKNOWN",
                        )
                    ).upper(),
                )

                st.markdown(
                    "**Target**"
                )

                st.code(
                    str(
                        match.get(
                            "target",
                            "",
                        )
                    )
                )

                st.markdown(
                    "**Matched Observable**"
                )

                st.code(
                    str(
                        match.get(
                            "observable_value",
                            "",
                        )
                    )
                )

                st.caption(
                    "Type: "
                    + str(
                        match.get(
                            "observable_type",
                            "unknown",
                        )
                    )
                    + " · Source: "
                    + str(
                        match.get(
                            "source",
                            "unknown",
                        )
                    )
                    + " · Created: "
                    + str(
                        match.get(
                            "created_at",
                            "unknown",
                        )
                    )
                )

    with st.expander(
        "🔐 Threat Hunting Trust Boundary"
    ):
        st.markdown(
            """
- Historical reports are searched deterministically.
- Exact normalized observable matching is used.
- Threat hunting does not rerun detection.
- Threat hunting does not modify historical verdicts.
- No AI is used to decide matches.
- No external threat-intelligence lookup occurs during the hunt.
- A historical match indicates shared evidence, not proof of common threat actor.
            """
        )

        trust1, trust2, trust3 = st.columns(
            3
        )

        trust1.metric(
            "AI Used",
            (
                "YES"
                if metadata.get(
                    "ai_used"
                )
                else "NO"
            ),
        )

        trust2.metric(
            "External Lookup",
            (
                "YES"
                if metadata.get(
                    "external_lookup_used"
                )
                else "NO"
            ),
        )

        trust3.metric(
            "Verdict Modified",
            (
                "YES"
                if metadata.get(
                    "verdict_modified"
                )
                else "NO"
            ),
        )


# ============================================================
# Existing platform information
# ============================================================

st.divider()

with st.expander(
    "Platform Modules"
):
    st.markdown(
        """
- **Unified Email Security Pipeline** — analyze a complete email.
- **Unified Domain Profile** — inspect a URL or domain.
- **Attachment and QR Inspection** — inspect uploaded files safely.
- **Gmail Observation Mode** — review Gmail messages without changing them.
- **Gmail Label Dry Run** — preview proposed labels.
- **Apply Gmail Labels** — apply explicitly approved actions.
- **Human Review / Feedback** — correct detections.
- **Accuracy Benchmark** — run deterministic regression evaluation.
- **Model Governance** — inspect reviewed training data and candidates.
"""
    )


with st.expander(
    "Safety Boundaries"
):
    st.code(
        "automatic_model_replacement: false\n"
        "unreviewed_mail_used_for_training: false\n"
        "attachment_execution: false\n"
        "automatic_quarantine: false\n"
        "gmail_changes_require_approval: true\n"
        "ai_creates_security_evidence: false"
    )


if benchmark:
    with st.expander(
        "Latest Regression Benchmark"
    ):
        metrics = benchmark.get(
            "current_threshold_metrics",
            {},
        )

        st.json(
            {
                "case_count": benchmark.get(
                    "case_count"
                ),

                "current_threshold": benchmark.get(
                    "current_threshold"
                ),

                "accuracy": metrics.get(
                    "accuracy"
                ),

                "precision": metrics.get(
                    "precision"
                ),

                "recall": metrics.get(
                    "recall"
                ),

                "false_positive_rate": (
                    metrics.get(
                        "false_positive_rate"
                    )
                ),

                "real_world_accuracy_claim": (
                    benchmark.get(
                        "real_world_accuracy_claim",
                        False,
                    )
                ),
            }
        )


st.caption(
    "Development mode · Mock analyst provider · "
    "No paid AI API required."
)
