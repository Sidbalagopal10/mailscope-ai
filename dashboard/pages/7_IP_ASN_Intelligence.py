from __future__ import annotations

from urllib.parse import quote

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="IP and ASN Intelligence",
    page_icon="��",
    layout="wide",
)

st.title(
    "🌐 IP and ASN Intelligence"
)

st.caption(
    "Resolve public infrastructure, origin ASNs, network names "
    "and reverse-DNS evidence. Infrastructure ownership does not "
    "automatically prove domain legitimacy."
)


def api_get(
    path: str,
    *,
    timeout: int = 90,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/ip-asn-intelligence/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )
    st.stop()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Observed Hostnames",
    summary.get(
        "observed_hostnames",
        0,
    ),
)

col2.metric(
    "Successful Lookups",
    summary.get(
        "successful_lookups",
        0,
    ),
)

col3.metric(
    "Unique ASNs",
    summary.get(
        "unique_asns",
        0,
    ),
)

col4.metric(
    "Network Owners",
    summary.get(
        "unique_network_names",
        0,
    ),
)


lookup_tab, history_tab = st.tabs(
    [
        "Infrastructure Lookup",
        "Observation History",
    ]
)


with lookup_tab:
    hostname = st.text_input(
        "Domain or hostname",
        placeholder="example.org",
    )

    force_refresh = st.checkbox(
        "Refresh cached network intelligence"
    )

    if st.button(
        "Analyze Infrastructure",
        type="primary",
        width="stretch",
    ):
        if not hostname.strip():
            st.warning(
                "Enter a hostname."
            )

        else:
            try:
                result = api_get(
                    (
                        "/ip-asn-intelligence/lookup"
                        f"?hostname={quote(hostname.strip(), safe='')}"
                        f"&force="
                        f"{'true' if force_refresh else 'false'}"
                    )
                )

                observation = result[
                    "observation"
                ]

                evidence = result[
                    "risk_evidence"
                ]

                if observation.get(
                    "lookup_status"
                ) == "success":
                    st.success(
                        "Public network infrastructure resolved."
                    )

                else:
                    st.warning(
                        "Only limited network evidence was available."
                    )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "Public IPs",
                    len(
                        observation.get(
                            "public_addresses",
                            [],
                        )
                    ),
                )

                metric2.metric(
                    "Origin ASNs",
                    len(
                        observation.get(
                            "unique_asns",
                            [],
                        )
                    ),
                )

                metric3.metric(
                    "Network Names",
                    len(
                        observation.get(
                            "unique_network_names",
                            [],
                        )
                    ),
                )

                metric4.metric(
                    "Risk Adjustment",
                    evidence.get(
                        "risk_adjustment",
                        0,
                    ),
                )

                st.subheader(
                    "Resolved Infrastructure"
                )

                st.json(
                    {
                        "hostname": observation.get(
                            "hostname"
                        ),
                        "ipv4_addresses": observation.get(
                            "ipv4_addresses"
                        ),
                        "ipv6_addresses": observation.get(
                            "ipv6_addresses"
                        ),
                        "public_addresses": observation.get(
                            "public_addresses"
                        ),
                        "unique_asns": observation.get(
                            "unique_asns"
                        ),
                        "unique_network_names": observation.get(
                            "unique_network_names"
                        ),
                        "reverse_dns": observation.get(
                            "reverse_dns"
                        ),
                        "cache_status": observation.get(
                            "cache_status"
                        ),
                    }
                )

                st.subheader(
                    "Detailed ASN Records"
                )

                st.json(
                    observation.get(
                        "asn_records",
                        [],
                    )
                )

                st.subheader(
                    "Bounded Security Evidence"
                )

                st.json(
                    evidence
                )

                st.info(
                    "Cloudflare, AWS, Microsoft, Google, Akamai "
                    "and other networks host many unrelated tenants. "
                    "Provider identity must never be treated as proof "
                    "that a domain is legitimate."
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


with history_tab:
    try:
        observations = api_get(
            "/ip-asn-intelligence/observations?limit=1000"
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

        visible_columns = [
            "hostname",
            "lookup_status",
            "public_addresses",
            "unique_asns",
            "unique_network_names",
            "observed_at",
        ]

        available_columns = [
            column
            for column in visible_columns
            if column in frame.columns
        ]

        st.dataframe(
            frame[
                available_columns
            ],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No network observations have been stored yet."
        )
