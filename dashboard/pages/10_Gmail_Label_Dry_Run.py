from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Gmail Label Dry Run",
    page_icon="🏷️",
    layout="wide",
)

st.title(
    "🏷️ Gmail Label Recommendation — Dry Run"
)

st.warning(
    "This page does not modify Gmail. It only shows the "
    "labels and escalation actions the detector would recommend."
)


def api_get(
    path: str,
    *,
    timeout: int = 120,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


if st.button(
    "Generate Label Plan",
    type="primary",
    width="stretch",
):
    try:
        with st.spinner(
            "Building an auditable label recommendation plan..."
        ):
            plan = api_get(
                "/gmail-label-plan/latest"
            )

        summary = plan.get(
            "summary",
            {},
        )

        metric1, metric2, metric3, metric4, metric5 = st.columns(5)

        metric1.metric(
            "Messages",
            summary.get(
                "messages_planned",
                0,
            ),
        )

        metric2.metric(
            "Moderate",
            summary.get(
                "moderate",
                0,
            ),
        )

        metric3.metric(
            "High",
            summary.get(
                "high",
                0,
            ),
        )

        metric4.metric(
            "Critical",
            summary.get(
                "critical",
                0,
            ),
        )

        metric5.metric(
            "Human Review",
            summary.get(
                "human_review_required",
                0,
            ),
        )

        rows = []

        for item in plan.get(
            "plans",
            [],
        ):
            rows.append(
                {
                    "subject": item.get(
                        "subject"
                    ),
                    "sender": item.get(
                        "sender_address"
                    ),
                    "risk_score": item.get(
                        "risk_score"
                    ),
                    "risk_level": item.get(
                        "risk_level"
                    ),
                    "labels": ", ".join(
                        item.get(
                            "proposed_labels",
                            [],
                        )
                    ),
                    "escalation": item.get(
                        "proposed_escalation"
                    ),
                    "human_review": item.get(
                        "human_review_required"
                    ),
                    "normal_urgency": item.get(
                        "authenticated_normal_urgency"
                    ),
                    "threat_match": item.get(
                        "threat_match"
                    ),
                    "brand_impersonation": item.get(
                        "brand_impersonation"
                    ),
                    "authentication_failed": item.get(
                        "authentication_failed"
                    ),
                }
            )

        if rows:
            st.dataframe(
                pd.DataFrame(
                    rows
                ),
                width="stretch",
                hide_index=True,
            )

        for index, item in enumerate(
            plan.get(
                "plans",
                [],
            ),
            start=1,
        ):
            title = (
                f"{index}. "
                f"[{str(item.get('risk_level', 'low')).upper()}] "
                f"{item.get('subject') or '(No subject)'}"
            )

            with st.expander(
                title
            ):
                st.write(
                    "**Proposed labels:** "
                    + ", ".join(
                        item.get(
                            "proposed_labels",
                            [],
                        )
                    )
                )

                st.write(
                    "**Proposed escalation:** "
                    + str(
                        item.get(
                            "proposed_escalation"
                        )
                    )
                )

                st.write(
                    "**Human review required:** "
                    + str(
                        item.get(
                            "human_review_required"
                        )
                    )
                )

                st.json(
                    item
                )

        st.success(
            "Dry-run plan generated. Gmail was not modified."
        )

        st.code(
            "dry_run: true\ngmail_modified: false"
        )

    except requests.HTTPError as error:
        try:
            detail = error.response.json().get(
                "detail",
                str(
                    error
                ),
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
