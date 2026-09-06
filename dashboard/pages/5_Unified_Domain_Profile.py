from __future__ import annotations

from urllib.parse import quote

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Unified Domain Profile",
    page_icon="🧠",
    layout="wide",
)

st.title(
    "🧠 Unified Domain Security Profile"
)

st.caption(
    "Combine organization identity, ML, URL heuristics, "
    "brand intelligence, RDAP, certificate history and DNS "
    "into one explainable verdict."
)


def api_get(
    path: str,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=120,
    )

    response.raise_for_status()

    return response.json()


value = st.text_input(
    "URL or domain",
    placeholder="https://example.org/login",
)

col_a, col_b = st.columns(2)

force_refresh = col_a.checkbox(
    "Refresh cached intelligence"
)

include_ct_subdomains = col_b.checkbox(
    "Include subdomains in CT lookup",
    value=False,
)

if st.button(
    "Build Unified Profile",
    type="primary",
    width="stretch",
):
    if not value.strip():
        st.warning(
            "Enter a URL or domain."
        )

    else:
        encoded_value = quote(
            value.strip(),
            safe="",
        )

        path = (
            "/unified-domain-profile/analyze"
            f"?value={encoded_value}"
            f"&force_refresh="
            f"{'true' if force_refresh else 'false'}"
            f"&include_ct_subdomains="
            f"{'true' if include_ct_subdomains else 'false'}"
        )

        try:
            with st.spinner(
                "Collecting URL, organization, registration, "
                "certificate and DNS evidence..."
            ):
                result = api_get(
                    path
                )

            classification = result.get(
                "classification",
                "unknown",
            )

            if result.get(
                "is_phishing"
            ):
                st.error(
                    "Likely phishing based on multiple "
                    "security evidence sources."
                )

            elif result.get(
                "is_suspicious"
            ):
                st.warning(
                    "Suspicious evidence was detected."
                )

            elif classification == "needs_review":
                st.info(
                    "The available evidence is inconclusive."
                )

            else:
                st.success(
                    "No strong phishing evidence was detected."
                )

            metric1, metric2, metric3, metric4 = st.columns(4)

            metric1.metric(
                "Final Risk Score",
                (
                    f"{result.get('final_score', 0):.1f}/100"
                ),
            )

            metric2.metric(
                "Risk Level",
                str(
                    result.get(
                        "risk_level",
                        "unknown",
                    )
                ).upper(),
            )

            metric3.metric(
                "Classification",
                str(
                    classification
                ).replace(
                    "_",
                    " ",
                ).title(),
            )

            metric4.metric(
                "Confidence",
                (
                    f"{result.get('confidence_percentage', 0):.1f}%"
                ),
            )

            st.subheader(
                "Score Composition"
            )

            score1, score2, score3 = st.columns(3)

            score1.metric(
                "Hybrid Detector",
                result.get(
                    "base_hybrid_score",
                    0,
                ),
            )

            score2.metric(
                "Intelligence Adjustment",
                result.get(
                    "total_intelligence_adjustment",
                    0,
                ),
            )

            score3.metric(
                "Final Score",
                result.get(
                    "final_score",
                    0,
                ),
            )

            st.subheader(
                "Recommendation"
            )

            st.info(
                result.get(
                    "recommendation",
                    "",
                )
            )

            organization = result.get(
                "organization_intelligence",
                {},
            )

            organization_record = (
                organization.get(
                    "record"
                )
                or {}
            )

            st.subheader(
                "Organization Identity"
            )

            org1, org2, org3, org4 = st.columns(4)

            org1.metric(
                "Matched",
                (
                    "YES"
                    if organization.get(
                        "matched"
                    )
                    else "NO"
                ),
            )

            org2.metric(
                "Organization",
                organization_record.get(
                    "legal_name",
                    "Unknown",
                ),
            )

            org3.metric(
                "Identity State",
                organization.get(
                    "identity_state",
                    "UNKNOWN",
                ),
            )

            org4.metric(
                "Security State",
                organization.get(
                    "security_state",
                    "NEUTRAL",
                ),
            )

            rdap = result.get(
                "rdap_intelligence",
                {},
            )

            rdap_observation = (
                rdap.get(
                    "observation"
                )
                or {}
            )

            ct = result.get(
                "certificate_transparency",
                {},
            )

            ct_observation = (
                ct.get(
                    "observation"
                )
                or {}
            )

            dns = result.get(
                "dns_intelligence",
                {},
            )

            dns_observation = (
                dns.get(
                    "observation"
                )
                or {}
            )

            st.subheader(
                "Infrastructure Intelligence"
            )

            infra1, infra2, infra3, infra4 = st.columns(4)

            infra1.metric(
                "Domain Age",
                (
                    f"{rdap_observation.get('domain_age_days')} days"
                    if rdap_observation.get(
                        "domain_age_days"
                    )
                    is not None
                    else "Unknown"
                ),
            )

            infra2.metric(
                "CT Certificates",
                ct_observation.get(
                    "certificate_count",
                    0,
                ),
            )

            infra3.metric(
                "MX Records",
                dns_observation.get(
                    "mx_count",
                    0,
                ),
            )

            infra4.metric(
                "DNSSEC",
                (
                    "PRESENT"
                    if (
                        dns_observation.get(
                            "has_dnssec_delegation"
                        )
                        or rdap_observation.get(
                            "dnssec_state"
                        )
                        == "signed"
                    )
                    else "NOT OBSERVED"
                ),
            )

            mail1, mail2, mail3 = st.columns(3)

            mail1.metric(
                "SPF",
                (
                    "PRESENT"
                    if dns_observation.get(
                        "has_spf"
                    )
                    else "NOT OBSERVED"
                ),
            )

            mail2.metric(
                "DMARC",
                (
                    "PRESENT"
                    if dns_observation.get(
                        "has_dmarc"
                    )
                    else "NOT OBSERVED"
                ),
            )

            mail3.metric(
                "CAA",
                (
                    "PRESENT"
                    if dns_observation.get(
                        "has_caa"
                    )
                    else "NOT OBSERVED"
                ),
            )

            evidence_tab, hybrid_tab, org_tab, rdap_tab, ct_tab, dns_tab = (
                st.tabs(
                    [
                        "Evidence Summary",
                        "Hybrid Detector",
                        "Organization",
                        "RDAP",
                        "Certificates",
                        "DNS",
                    ]
                )
            )

            with evidence_tab:
                st.json(
                    {
                        "evidence_summary": result.get(
                            "evidence_summary"
                        ),
                        "reasons": result.get(
                            "reasons"
                        ),
                        "unavailable_sources": result.get(
                            "unavailable_sources"
                        ),
                        "limitations": result.get(
                            "limitations"
                        ),
                    }
                )

            with hybrid_tab:
                st.json(
                    result.get(
                        "hybrid_detection",
                        {},
                    )
                )

            with org_tab:
                st.json(
                    organization
                )

            with rdap_tab:
                st.json(
                    rdap
                )

            with ct_tab:
                st.json(
                    ct
                )

            with dns_tab:
                st.json(
                    dns
                )

        except requests.HTTPError as error:
            try:
                detail = (
                    error.response.json().get(
                        "detail",
                        str(
                            error
                        ),
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
