from __future__ import annotations

from urllib.parse import quote

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Gmail Observation Mode",
    page_icon="👁️",
    layout="wide",
)

st.title(
    "👁️ Gmail Observation Mode"
)

st.warning(
    "Observation-only mode: this page does not add labels, "
    "archive, delete, quarantine, or otherwise modify Gmail."
)


def api_get(
    path: str,
    *,
    timeout: int = 300,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


max_results = st.slider(
    "Number of recent messages",
    min_value=1,
    max_value=25,
    value=10,
)

query = st.text_input(
    "Gmail search query",
    value="in:inbox newer_than:14d",
)

if st.button(
    "Analyze Recent Messages",
    type="primary",
    width="stretch",
):
    try:
        with st.spinner(
            "Reading message headers, authentication, "
            "context, threads, and links..."
        ):
            report = api_get(
                (
                    "/gmail-observation/recent"
                    f"?max_results={max_results}"
                    f"&query={quote(query, safe='')}"
                )
            )

        summary = report.get(
            "summary",
            {},
        )

        metric1, metric2, metric3, metric4, metric5 = st.columns(5)

        metric1.metric(
            "Analyzed",
            summary.get(
                "messages_analyzed",
                0,
            ),
        )

        metric2.metric(
            "Low",
            summary.get(
                "low",
                0,
            ),
        )

        metric3.metric(
            "Moderate",
            summary.get(
                "moderate",
                0,
            ),
        )

        metric4.metric(
            "High",
            summary.get(
                "high",
                0,
            ),
        )

        metric5.metric(
            "Critical",
            summary.get(
                "critical",
                0,
            ),
        )

        rows = []

        for message in report.get(
            "messages",
            [],
        ):
            decision = message.get(
                "contextual_decision",
                {},
            )

            authentication = message.get(
                "authentication",
                {},
            )

            intent = decision.get(
                "message_context",
                {},
            ).get(
                "intent",
                {},
            )

            urgency = decision.get(
                "message_context",
                {},
            ).get(
                "urgency",
                {},
            )

            rows.append(
                {
                    "subject": message.get(
                        "subject"
                    ),
                    "sender": message.get(
                        "sender_address"
                    ),
                    "risk_score": decision.get(
                        "risk_score"
                    ),
                    "risk_level": decision.get(
                        "risk_level"
                    ),
                    "intent": intent.get(
                        "primary_intent"
                    ),
                    "urgency": urgency.get(
                        "level"
                    ),
                    "spf": authentication.get(
                        "spf",
                        {},
                    ).get(
                        "result"
                    ),
                    "dkim": authentication.get(
                        "dkim",
                        {},
                    ).get(
                        "result"
                    ),
                    "dmarc": authentication.get(
                        "dmarc",
                        {},
                    ).get(
                        "result"
                    ),
                    "known_sender": message.get(
                        "known_sender"
                    ),
                    "existing_thread": message.get(
                        "existing_thread"
                    ),
                    "url_count": message.get(
                        "url_count"
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

        for index, message in enumerate(
            report.get(
                "messages",
                [],
            ),
            start=1,
        ):
            decision = message.get(
                "contextual_decision",
                {},
            )

            title = (
                f"{index}. "
                f"[{str(decision.get('risk_level', 'unknown')).upper()}] "
                f"{message.get('subject') or '(No subject)'}"
            )

            with st.expander(
                title
            ):
                st.write(
                    f"**From:** {message.get('from_header')}"
                )

                st.write(
                    f"**Risk:** {decision.get('risk_score')} / 100"
                )

                st.write(
                    f"**Recommendation:** "
                    f"{decision.get('recommendation')}"
                )

                st.write(
                    f"**Known sender:** "
                    f"{message.get('known_sender')}"
                )

                st.write(
                    f"**Existing thread:** "
                    f"{message.get('existing_thread')}"
                )

                st.write(
                    f"**URLs found:** "
                    f"{message.get('url_count')}"
                )

                st.json(
                    {
                        "authentication": message.get(
                            "authentication"
                        ),
                        "contextual_decision": decision,
                        "urls": message.get(
                            "urls"
                        ),
                        "body_preview": message.get(
                            "body_preview"
                        ),
                        "observation_only": message.get(
                            "observation_only"
                        ),
                        "gmail_modified": message.get(
                            "gmail_modified"
                        ),
                    }
                )

        if report.get(
            "errors"
        ):
            st.subheader(
                "Messages that could not be analyzed"
            )

            st.json(
                report[
                    "errors"
                ]
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
