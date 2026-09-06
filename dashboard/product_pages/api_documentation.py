from __future__ import annotations

import streamlit as st

from dashboard.core.api_client import (
    api_base_url,
    health_status,
)


def render() -> None:
    st.set_page_config(
        page_title="API Documentation",
        page_icon="📚",
        layout="wide",
    )

    st.title(
        "📚 API Documentation"
    )

    status = health_status()

    docs_url = (
        f"{api_base_url()}/docs"
    )

    openapi_url = (
        f"{api_base_url()}/openapi.json"
    )

    if status.get(
        "available"
    ):
        st.success(
            "FastAPI is online."
        )

        st.link_button(
            "Open Swagger API Documentation",
            docs_url,
            use_container_width=True,
        )

        st.link_button(
            "Open OpenAPI JSON",
            openapi_url,
            use_container_width=True,
        )

        st.metric(
            "Registered API Routes",
            status.get(
                "route_count",
                0,
            ),
        )

    else:
        st.error(
            "FastAPI is offline."
        )

        st.code(
            "./run_app.sh"
        )

    st.subheader(
        "Primary API"
    )

    st.code(
        "POST /email-security-pipeline/analyze"
    )

    st.write(
        "This is the canonical end-to-end analysis endpoint "
        "for the dashboard and future Gmail extension."
    )

    st.subheader(
        "Security boundaries"
    )

    st.markdown(
        """
        - The unified pipeline does not modify Gmail.
        - Attachment inspection does not execute uploaded files.
        - External intelligence failures remain neutral.
        - Gmail label execution requires explicit confirmation.
        - Model promotion and rollback require exact confirmation phrases.
        """
    )
