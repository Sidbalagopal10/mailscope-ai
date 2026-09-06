from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Any

from app.domain_intelligence.safe_unified_profile import (
    analyze_unified_domain_profile,
)
from app.domain_intelligence.enriched_profile import (
    analyze_enriched_domain_profile,
)
from app.threat_enrichment.models import (
    EnrichmentSource,
    ThreatEnrichment,
)
from app.threat_enrichment.normalizers import (
    extract_hostname,
    normalize_profile_source,
    normalize_unified_profile,
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _safe_unified_profile(
    target: str,
    *,
    force_refresh: bool,
    include_ct_subdomains: bool,
) -> tuple[
    dict[str, Any],
    str | None,
]:
    try:
        result = (
            analyze_unified_domain_profile(
                target,
                force_refresh=force_refresh,
                include_ct_subdomains=(
                    include_ct_subdomains
                ),
            )
        )

        if isinstance(
            result,
            dict,
        ):
            return result, None

        return {}, (
            "Unified profile returned "
            "an unexpected result type."
        )

    except Exception as error:
        return {}, (
            f"{type(error).__name__}: "
            f"{error}"
        )


def _safe_virustotal(
    target: str,
    *,
    force_refresh: bool,
) -> EnrichmentSource:
    """
    Reuse the project's existing enriched profile for
    VirusTotal instead of creating another VT client.

    Provider failure must never fail the investigation.
    """

    try:
        result = (
            analyze_enriched_domain_profile(
                target,
                force_refresh=force_refresh,
            )
        )

        if not isinstance(
            result,
            dict,
        ):
            return EnrichmentSource(
                source="virustotal",
                status="unavailable",
                summary=(
                    "VirusTotal intelligence "
                    "was not available."
                ),
            )

        vt = {}

        for key in (
            "virustotal",
            "virus_total",
            "virustotal_intelligence",
        ):
            candidate = result.get(
                key
            )

            if isinstance(
                candidate,
                dict,
            ):
                vt = candidate
                break

        return normalize_profile_source(
            source="virustotal",
            payload=vt,
        )

    except Exception as error:
        return EnrichmentSource(
            source="virustotal",
            status="error",
            summary=(
                "VirusTotal intelligence "
                "collection failed."
            ),
            error=(
                f"{type(error).__name__}: "
                f"{error}"
            ),
        )


def enrich_target(
    target: str,
    *,
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
) -> ThreatEnrichment:
    """
    Build normalized threat intelligence for a target.

    SECURITY BOUNDARY
    -----------------
    This function gathers and normalizes evidence.

    It does NOT:
      * change Core Engine severity,
      * declare unknown infrastructure malicious,
      * treat provider absence as suspicious,
      * allow a threat feed to override the detector,
      * call an LLM.

    Threat intelligence remains evidence.
    """

    hostname = extract_hostname(
        target
    )

    profile, profile_error = (
        _safe_unified_profile(
            target,
            force_refresh=force_refresh,
            include_ct_subdomains=(
                include_ct_subdomains
            ),
        )
    )

    if profile:
        sources = (
            normalize_unified_profile(
                profile
            )
        )

    else:
        sources = [
            EnrichmentSource(
                source=name,
                status="error",
                summary=(
                    "Unified intelligence "
                    "collection failed."
                ),
                error=profile_error,
            )

            for name in (
                "dns",
                "rdap",
                "certificate_transparency",
                "ip_asn",
                "threatfox",
            )
        ]

    sources.append(
        _safe_virustotal(
            target,
            force_refresh=force_refresh,
        )
    )

    return ThreatEnrichment(
        target=target,
        hostname=hostname,
        created_at=utc_now(),
        sources=sources,
        metadata={
            "orchestrator_version": (
                "2.0.0"
            ),

            "core_engine_modified": False,

            "ai_used": False,

            "threat_intelligence_is_evidence": (
                True
            ),

            "provider_failure_is_neutral": (
                True
            ),
        },
    )
