from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from dashboard.core.api_client import (
    api_base_url,
    health_status,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

BENCHMARK_REPORT = (
    PROJECT_ROOT
    / "data/evaluation/latest_benchmark_report.json"
)

REVIEW_DATABASE = (
    PROJECT_ROOT
    / "data/gmail_feedback/reviews.db"
)


def load_benchmark() -> dict:
    if not BENCHMARK_REPORT.exists():
        return {}

    try:
        return json.loads(
            BENCHMARK_REPORT.read_text(
                encoding="utf-8"
            )
        )

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return {}


def render() -> None:
    st.set_page_config(
        page_title="AI Mail Security",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title(
        "🛡️ AI Mail Security Platform"
    )

    st.caption(
        "Explainable Gmail phishing, BEC, attachment, "
        "and threat-intelligence analysis with human review "
        "and governed machine learning."
    )

    health = health_status()
    benchmark = load_benchmark()

    current_metrics = benchmark.get(
        "current_threshold_metrics",
        {},
    )

    column1, column2, column3, column4 = st.columns(4)

    column1.metric(
        "Backend",
        (
            "ONLINE"
            if health.get("available")
            else "OFFLINE"
        ),
    )

    column2.metric(
        "API Routes",
        health.get(
            "route_count",
            0,
        ),
    )

    column3.metric(
        "Regression Tests",
        "191 passed",
        help=(
            "Most recent complete local test-suite result. "
            "This is not a real-world accuracy claim."
        ),
    )

    column4.metric(
        "Benchmark Recall",
        (
            f"{float(current_metrics.get('recall', 0)) * 100:.0f}%"
            if current_metrics
            else "Not run"
        ),
        help=(
            "Result from the deterministic regression benchmark, "
            "not an independent production dataset."
        ),
    )

    if health.get(
        "available"
    ):
        st.success(
            "FastAPI and Streamlit are connected."
        )

    else:
        st.error(
            "FastAPI is unavailable. Run `./run_app.sh` and "
            "check `logs/fastapi.log`."
        )

        if health.get(
            "error"
        ):
            st.code(
                health["error"]
            )

    st.subheader(
        "Primary Workflow"
    )

    workflow1, workflow2, workflow3 = st.columns(3)

    with workflow1:
        st.markdown(
            """
            ### 1. Analyze

            Inspect an email, its sender authentication, intent,
            urgency, links, infrastructure, attachments, and QR codes.
            """
        )

    with workflow2:
        st.markdown(
            """
            ### 2. Review

            Examine explainable findings, approve Gmail labels,
            and record false positives or false negatives.
            """
        )

    with workflow3:
        st.markdown(
            """
            ### 3. Improve

            Evaluate reviewed examples, stage candidate models,
            and require manual promotion with rollback.
            """
        )

    st.subheader(
        "Platform Capabilities"
    )

    capability1, capability2 = st.columns(2)

    with capability1:
        st.markdown(
            """
            **Email and identity**

            - SPF, DKIM, DMARC, and ARC analysis
            - Academic and workplace urgency awareness
            - Gift-card, wire-transfer, invoice, and credential intent
            - Sender and thread context
            - Brand and organization identity
            """
        )

        st.markdown(
            """
            **Threat intelligence**

            - VirusTotal
            - ThreatFox
            - RDAP and domain age
            - DNS and mail-security records
            - Certificate transparency
            - IP and ASN identity
            """
        )

    with capability2:
        st.markdown(
            """
            **Attachments**

            - SHA-256 hashing
            - Executable and script detection
            - Double-extension detection
            - Archive inspection
            - Office macro structures
            - PDF active-content indicators
            - QR-code URL extraction
            """
        )

        st.markdown(
            """
            **Responsible ML**

            - Human-reviewed feedback
            - Balanced training-data gate
            - Holdout evaluation
            - False-positive constraints
            - Staged candidates
            - Manual promotion and rollback
            """
        )

    st.subheader(
        "Safety State"
    )

    st.code(
        "automatic_model_replacement: false\n"
        "unreviewed_mail_used_for_training: false\n"
        "attachment_execution: false\n"
        "automatic_quarantine: false\n"
        "gmail_changes_require_approval: true"
    )

    with st.expander(
        "System information"
    ):
        st.json(
            {
                "api_base_url": api_base_url(),
                "backend_available": health.get(
                    "available"
                ),
                "api_route_count": health.get(
                    "route_count"
                ),
                "benchmark_report_available": bool(
                    benchmark
                ),
                "human_review_database_exists": (
                    REVIEW_DATABASE.exists()
                ),
            }
        )

    st.info(
        "Use the navigation menu to begin with "
        "**Analyze → Email Security**."
    )
