from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="DNS Intelligence",
    page_icon="🧭",
    layout="wide",
)

st.title(
    "🧭 Global DNS Intelligence"
)

st.caption(
    "Inspect worldwide DNS, mail infrastructure, "
    "email-authentication policies, and bounded risk evidence."
)


def api_get(
    path: str,
    *,
    timeout: int = 60,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/dns-intelligence/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )

    st.stop()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Observed Domains",
    summary.get(
        "observed_domains",
        0,
    ),
)

col2.metric(
    "Domains With MX",
    summary.get(
        "domains_with_mx",
        0,
    ),
)

col3.metric(
    "Domains With SPF",
    summary.get(
        "domains_with_spf",
        0,
    ),
)

col4.metric(
    "Domains With DMARC",
    summary.get(
        "domains_with_dmarc",
        0,
    ),
)


lookup_tab, dkim_tab, history_tab = st.tabs(
    [
        "DNS Lookup",
        "DKIM Selector Check",
        "Observation History",
    ]
)


with lookup_tab:
    domain = st.text_input(
        "Domain",
        placeholder="example.org",
        key="dns_domain",
    )

    force_refresh = st.checkbox(
        "Refresh cached DNS data"
    )

    if st.button(
        "Analyze DNS",
        type="primary",
        width="stretch",
    ):
        if not domain.strip():
            st.warning(
                "Enter a domain."
            )

        else:
            try:
                payload = api_get(
                    (
                        "/dns-intelligence/lookup"
                        f"?domain={domain.strip()}"
                        f"&force="
                        f"{'true' if force_refresh else 'false'}"
                    )
                )

                observation = payload[
                    "observation"
                ]

                evidence = payload[
                    "risk_evidence"
                ]

                st.success(
                    "DNS analysis completed."
                )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "MX Records",
                    observation.get(
                        "mx_count",
                        0,
                    ),
                )

                metric2.metric(
                    "Nameservers",
                    observation.get(
                        "ns_count",
                        0,
                    ),
                )

                metric3.metric(
                    "DNSSEC Delegation",
                    (
                        "PRESENT"
                        if observation.get(
                            "has_dnssec_delegation"
                        )
                        else "NOT OBSERVED"
                    ),
                )

                metric4.metric(
                    "Risk Adjustment",
                    evidence.get(
                        "risk_adjustment",
                        0,
                    ),
                )

                auth1, auth2, auth3 = st.columns(3)

                auth1.metric(
                    "SPF",
                    (
                        "PRESENT"
                        if observation.get(
                            "has_spf"
                        )
                        else "NOT OBSERVED"
                    ),
                )

                auth2.metric(
                    "DMARC",
                    (
                        "PRESENT"
                        if observation.get(
                            "has_dmarc"
                        )
                        else "NOT OBSERVED"
                    ),
                )

                auth3.metric(
                    "CAA",
                    (
                        "PRESENT"
                        if observation.get(
                            "has_caa"
                        )
                        else "NOT OBSERVED"
                    ),
                )

                st.subheader(
                    "Mail Authentication"
                )

                st.json(
                    {
                        "spf_records": observation.get(
                            "spf_records",
                            [],
                        ),
                        "dmarc_records": observation.get(
                            "dmarc_records",
                            [],
                        ),
                        "dkim": (
                            "A selector is required. Use "
                            "the DKIM Selector Check tab."
                        ),
                    }
                )

                st.subheader(
                    "DNS Records"
                )

                records = observation.get(
                    "records",
                    {},
                )

                for record_type in (
                    "a",
                    "aaaa",
                    "mx",
                    "ns",
                    "cname",
                    "soa",
                    "caa",
                    "ds",
                    "txt",
                ):
                    with st.expander(
                        record_type.upper()
                    ):
                        values = records.get(
                            record_type,
                            [],
                        )

                        if values:
                            st.json(
                                values
                            )

                        else:
                            st.write(
                                "No record observed."
                            )

                st.subheader(
                    "Bounded Security Evidence"
                )

                st.json(
                    evidence
                )

                st.info(
                    "Missing MX, SPF, DMARC, CAA, or DNSSEC "
                    "cannot independently classify a domain as "
                    "phishing. Many legitimate domains do not "
                    "send mail or use every optional DNS feature."
                )

            except requests.HTTPError as error:
                try:
                    detail = (
                        error.response.json().get(
                            "detail"
                        )
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


with dkim_tab:
    dkim_domain = st.text_input(
        "Domain",
        placeholder="example.org",
        key="dkim_domain",
    )

    selector = st.text_input(
        "DKIM selector",
        placeholder=(
            "Optional: google, selector1, default"
        ),
    )

    if st.button(
        "Check DKIM",
        width="stretch",
    ):
        if not dkim_domain.strip():
            st.warning(
                "Enter a domain."
            )

        else:
            try:
                path = (
                    "/dns-intelligence/dkim"
                    f"?domain={dkim_domain.strip()}"
                )

                if selector.strip():
                    path += (
                        f"&selector="
                        f"{selector.strip()}"
                    )

                result = api_get(
                    path
                )

                if (
                    result.get(
                        "found"
                    )
                    or result.get(
                        "found_count",
                        0,
                    )
                    > 0
                ):
                    st.success(
                        "At least one DKIM record was found."
                    )

                else:
                    st.info(
                        "No tested DKIM selector was found. "
                        "This does not prove that DKIM is absent."
                    )

                st.json(
                    result
                )

            except requests.RequestException as error:
                st.error(
                    str(
                        error
                    )
                )


with history_tab:
    try:
        observations = api_get(
            "/dns-intelligence/observations?limit=1000"
        ).get(
            "observations",
            [],
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )

        observations = []

    if observations:
        frame = pd.DataFrame(
            observations
        )

        columns = [
            "domain",
            "registrable_domain",
            "lookup_status",
            "has_mx",
            "has_spf",
            "has_dmarc",
            "has_dnssec_delegation",
            "mx_count",
            "ns_count",
            "minimum_ttl",
            "observed_at",
        ]

        available = [
            column
            for column in columns
            if column in frame.columns
        ]

        st.dataframe(
            frame[
                available
            ],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No DNS observations have been stored yet."
        )
