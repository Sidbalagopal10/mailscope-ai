from __future__ import annotations

from app.domain_intelligence import (
    unified_profile,
)


def successful_lookup(
    result,
):
    return {
        "available": True,
        "result": result,
        "error": None,
    }


def test_verified_clean_organization_reduces_uncertainty(
    monkeypatch,
):
    monkeypatch.setattr(
        unified_profile,
        "safe_lookup",
        lambda function, *args, **kwargs: (
            successful_lookup(
                {
                    "final_score": 34.0,
                    "confidence_percentage": 53.0,
                    "reasons": [],
                    "corroborating_evidence": {
                        "strong_signal_count": 0,
                        "weak_signal_count": 0,
                    },
                    "brand_intelligence": {
                        "impersonation_detected": False
                    },
                }
            )
            if function
            is unified_profile.analyze_url_hybrid
            else successful_lookup(
                {
                    "matched": True,
                    "identity_state": (
                        "VERIFIED_ESTABLISHED"
                    ),
                    "security_state": "NEUTRAL",
                    "score_adjustment": -18.0,
                    "identity_confidence": 96.0,
                    "security_confidence": 50.0,
                    "reasons": [
                        "Verified organization"
                    ],
                    "record": {
                        "legal_name": (
                            "Example University"
                        )
                    },
                }
            )
            if function
            is unified_profile.identity_score_adjustment
            else successful_lookup(
                {
                    "lookup_status": "success",
                    "domain_age_days": 5000,
                    "domain_status": [],
                    "dnssec_state": "signed",
                    "registrar_name": (
                        "Example Registrar"
                    ),
                }
            )
            if function
            is unified_profile.lookup_rdap
            else successful_lookup(
                {
                    "lookup_status": "success",
                    "certificate_count": 20,
                    "first_seen": (
                        "2010-01-01T00:00:00+00:00"
                    ),
                    "last_seen": (
                        "2026-01-01T00:00:00+00:00"
                    ),
                }
            )
            if function
            is unified_profile.lookup_ct
            else successful_lookup(
                {
                    "lookup_status": "success",
                    "has_a": True,
                    "has_aaaa": True,
                    "has_mx": True,
                    "has_spf": True,
                    "has_dmarc": True,
                    "has_caa": True,
                    "has_dnssec_delegation": True,
                    "mx_count": 3,
                    "ns_count": 4,
                }
            )
        ),
    )

    result = (
        unified_profile.analyze_unified_domain_profile(
            "https://example.edu/"
        )
    )

    assert result[
        "final_score"
    ] < 20

    assert (
        result["classification"]
        == "likely_legitimate"
    )

    assert result[
        "organization_intelligence"
    ][
        "matched"
    ]


def test_positive_history_does_not_override_impersonation(
    monkeypatch,
):
    def fake_safe_lookup(
        function,
        *args,
        **kwargs,
    ):
        if (
            function
            is unified_profile.analyze_url_hybrid
        ):
            return successful_lookup(
                {
                    "final_score": 78.0,
                    "confidence_percentage": 90.0,
                    "reasons": [],
                    "corroborating_evidence": {
                        "strong_signal_count": 2,
                        "weak_signal_count": 1,
                    },
                    "brand_intelligence": {
                        "impersonation_detected": True
                    },
                }
            )

        if (
            function
            is unified_profile.identity_score_adjustment
        ):
            return successful_lookup(
                {
                    "matched": True,
                    "identity_state": (
                        "VERIFIED_ESTABLISHED"
                    ),
                    "security_state": "NEUTRAL",
                    "score_adjustment": -18.0,
                    "identity_confidence": 95.0,
                    "security_confidence": 50.0,
                    "reasons": [],
                    "record": {},
                }
            )

        if function is unified_profile.lookup_rdap:
            return successful_lookup(
                {
                    "lookup_status": "success",
                    "domain_age_days": 5000,
                    "domain_status": [],
                    "dnssec_state": "signed",
                    "registrar_name": "Registrar",
                }
            )

        if function is unified_profile.lookup_ct:
            return successful_lookup(
                {
                    "lookup_status": "success",
                    "certificate_count": 20,
                    "first_seen": (
                        "2010-01-01T00:00:00+00:00"
                    ),
                    "last_seen": (
                        "2026-01-01T00:00:00+00:00"
                    ),
                }
            )

        return successful_lookup(
            {
                "lookup_status": "success",
                "has_a": True,
                "has_aaaa": True,
                "has_mx": True,
                "has_spf": True,
                "has_dmarc": True,
                "has_caa": True,
                "has_dnssec_delegation": True,
                "mx_count": 3,
                "ns_count": 4,
            }
        )

    monkeypatch.setattr(
        unified_profile,
        "safe_lookup",
        fake_safe_lookup,
    )

    result = (
        unified_profile.analyze_unified_domain_profile(
            (
                "https://linkedln-login."
                "example.com/verify"
            )
        )
    )

    assert result[
        "is_phishing"
    ]

    assert result[
        "final_score"
    ] >= 70

    assert result[
        "organization_intelligence"
    ][
        "adjustment_blocked"
    ]


def test_failed_external_sources_remain_neutral(
    monkeypatch,
):
    def fake_safe_lookup(
        function,
        *args,
        **kwargs,
    ):
        if (
            function
            is unified_profile.analyze_url_hybrid
        ):
            return successful_lookup(
                {
                    "final_score": 34.0,
                    "confidence_percentage": 53.0,
                    "reasons": [],
                    "corroborating_evidence": {
                        "strong_signal_count": 0,
                        "weak_signal_count": 0,
                    },
                    "brand_intelligence": {
                        "impersonation_detected": False
                    },
                }
            )

        if (
            function
            is unified_profile.identity_score_adjustment
        ):
            return successful_lookup(
                {
                    "matched": False,
                    "identity_state": "UNKNOWN",
                    "security_state": "NEUTRAL",
                    "score_adjustment": 0.0,
                    "identity_confidence": 0.0,
                    "security_confidence": 0.0,
                    "reasons": [],
                    "record": None,
                }
            )

        return {
            "available": False,
            "result": None,
            "error": "Service unavailable",
        }

    monkeypatch.setattr(
        unified_profile,
        "safe_lookup",
        fake_safe_lookup,
    )

    result = (
        unified_profile.analyze_unified_domain_profile(
            "https://unknown.example/"
        )
    )

    assert result[
        "final_score"
    ] == 34.0

    unavailable_sources = result[
        "unavailable_sources"
    ]

    assert len(
        unavailable_sources
    ) == 7

    assert {
        item[
            "source"
        ]
        for item in unavailable_sources
    } == {
        "Global Brand Intelligence",
        "RDAP",
        "Certificate Transparency",
        "DNS Intelligence",
        "IP and ASN Intelligence",
        "ThreatFox URL Intelligence",
        "ThreatFox Domain Intelligence",
    }
