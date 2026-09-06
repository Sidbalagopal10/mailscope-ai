from __future__ import annotations

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Unified Email Security Pipeline",
    page_icon="🛡️",
    layout="wide",
)

st.title(
    "🛡️ Unified Email Security Pipeline"
)

st.caption(
    "Canonical end-to-end analysis combining authentication, "
    "message context, links, threat intelligence, model governance, "
    "and Gmail label recommendations."
)

st.info(
    "Analysis-only mode: this page does not modify Gmail."
)


def api_post(
    path: str,
    payload: dict,
):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        json=payload,
        timeout=600,
    )

    response.raise_for_status()

    return response.json()


with st.form(
    "unified_email_form"
):
    subject = st.text_input(
        "Subject",
        value="Urgent: Assignment due tonight",
    )

    sender = st.text_input(
        "Sender",
        value=(
            "Professor Example "
            "<professor@example.edu>"
        ),
    )

    body = st.text_area(
        "Email body",
        value=(
            "Please submit Assignment 3 through Blackboard "
            "by 11:59 PM tonight."
        ),
        height=200,
    )

    authentication_results = st.text_area(
        "Authentication-Results header",
        value=(
            "mx.google.com; "
            "spf=pass smtp.mailfrom=example.edu; "
            "dkim=pass header.d=example.edu; "
            "dmarc=pass header.from=example.edu"
        ),
        height=120,
    )

    optional_urls = st.text_area(
        "Optional URLs, one per line",
        value="",
        height=100,
    )

    column1, column2, column3 = st.columns(3)

    with column1:
        known_sender = st.checkbox(
            "Known sender",
            value=True,
        )

    with column2:
        existing_thread = st.checkbox(
            "Existing thread",
            value=True,
        )

    with column3:
        sender_domain_verified = st.checkbox(
            "Verified sender domain",
            value=True,
        )

    attachment_risk_score = st.slider(
        "Attachment risk score",
        min_value=0.0,
        max_value=100.0,
        value=0.0,
    )

    enable_virustotal = st.checkbox(
        "Enable selective VirusTotal intelligence",
        value=True,
    )

    force_refresh = st.checkbox(
        "Force external-intelligence refresh",
        value=False,
    )

    submitted = st.form_submit_button(
        "Analyze Email",
        type="primary",
        width="stretch",
    )


if submitted:
    headers = [
        {
            "name": "From",
            "value": sender,
        }
    ]

    if authentication_results.strip():
        headers.append(
            {
                "name": "Authentication-Results",
                "value": (
                    authentication_results.strip()
                ),
            }
        )

    urls = [
        line.strip()
        for line in optional_urls.splitlines()
        if line.strip()
    ]

    try:
        with st.spinner(
            "Running the unified email-security pipeline..."
        ):
            result = api_post(
                "/email-security-pipeline/analyze",
                {
                    "subject": subject,
                    "body": body,
                    "headers": headers,
                    "urls": urls,
                    "sender_address": sender,
                    "known_sender": (
                        known_sender
                    ),
                    "existing_thread": (
                        existing_thread
                    ),
                    "sender_domain_verified": (
                        sender_domain_verified
                    ),
                    "attachment_risk_score": (
                        attachment_risk_score
                    ),
                    "maximum_deep_urls": 5,
                    "force_refresh": (
                        force_refresh
                    ),
                    "enable_virustotal": (
                        enable_virustotal
                    ),
                },
            )

        decision = result.get(
            "final_decision",
            {},
        )

        evidence = result.get(
            "evidence_summary",
            {},
        )

        labels = result.get(
            "label_recommendation",
            {},
        )

        metric1, metric2, metric3, metric4 = st.columns(4)

        metric1.metric(
            "Final Score",
            decision.get(
                "risk_score",
                0,
            ),
        )

        metric2.metric(
            "Risk Level",
            str(
                decision.get(
                    "risk_level",
                    "unknown",
                )
            ).upper(),
        )

        metric3.metric(
            "URLs",
            evidence.get(
                "url_count",
                0,
            ),
        )

        metric4.metric(
            "Human Review",
            (
                "YES"
                if evidence.get(
                    "human_review_required"
                )
                else "NO"
            ),
        )

        if decision.get(
            "risk_level"
        ) in {
            "high",
            "critical",
        }:
            st.error(
                decision.get(
                    "recommendation"
                )
            )

        elif decision.get(
            "risk_level"
        ) == "moderate":
            st.warning(
                decision.get(
                    "recommendation"
                )
            )

        else:
            st.success(
                decision.get(
                    "recommendation"
                )
            )

        tab1, tab2, tab3, tab4, tab5 = st.tabs(
            [
                "Final Verdict",
                "Authentication and Context",
                "Deep URL Analysis",
                "Label Recommendation",
                "Complete Result",
            ]
        )

        with tab1:
            st.json(
                {
                    "risk_score": decision.get(
                        "risk_score"
                    ),
                    "risk_level": decision.get(
                        "risk_level"
                    ),
                    "classification": (
                        decision.get(
                            "classification"
                        )
                    ),
                    "is_phishing": decision.get(
                        "is_phishing"
                    ),
                    "recommendation": (
                        decision.get(
                            "recommendation"
                        )
                    ),
                    "suspicious_signals": (
                        decision.get(
                            "suspicious_signals"
                        )
                    ),
                    "positive_signals": (
                        decision.get(
                            "positive_signals"
                        )
                    ),
                    "reasons": decision.get(
                        "reasons"
                    ),
                }
            )

        with tab2:
            st.json(
                {
                    "authentication": (
                        result.get(
                            "authentication"
                        )
                    ),
                    "message_context": (
                        decision.get(
                            "message_context"
                        )
                    ),
                    "known_sender": (
                        result.get(
                            "message",
                            {},
                        ).get(
                            "known_sender"
                        )
                    ),
                    "existing_thread": (
                        result.get(
                            "message",
                            {},
                        ).get(
                            "existing_thread"
                        )
                    ),
                    "sender_domain_verified": (
                        result.get(
                            "message",
                            {},
                        ).get(
                            "sender_domain_verified"
                        )
                    ),
                }
            )

        with tab3:
            st.json(
                result.get(
                    "deep_link_analysis"
                )
            )

        with tab4:
            st.write(
                "**Proposed labels:** "
                + ", ".join(
                    labels.get(
                        "proposed_labels",
                        [],
                    )
                )
            )

            st.json(
                labels
            )

        with tab5:
            st.json(
                result
            )

        st.code(
            "analysis_only: true\n"
            "gmail_modified: false"
        )

    except requests.HTTPError as error:
        try:
            detail = error.response.json().get(
                "detail",
                str(error),
            )

        except ValueError:
            detail = str(
                error
            )

        st.error(
            detail
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )
