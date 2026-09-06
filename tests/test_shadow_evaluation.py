from __future__ import annotations

from app.shadow_evaluation.domain_bridge import (
    impersonation_from_old_result,
    threatfox_from_old_result,
    virustotal_from_old_result,
)


def test_old_threatfox_adapter():
    result = threatfox_from_old_result(
        {
            "threatfox_intelligence": {
                "matched": True,
                "relevance_validated": False,
                "domain_lookup": {
                    "observation": {
                        "maximum_confidence": 100,
                        "matches": 26,
                    }
                },
            }
        }
    )

    assert result[
        "matched"
    ] is True

    assert result[
        "exact_relevance"
    ] is False

    assert result[
        "confidence"
    ] == 1.0


def test_old_virustotal_adapter():
    result = virustotal_from_old_result(
        {
            "virustotal_intelligence": {
                "maximum_malicious": 1,
                "maximum_suspicious": 2,
                "maximum_harmless": 80,
            }
        }
    )

    assert result[
        "malicious"
    ] == 1

    assert result[
        "suspicious"
    ] == 2


def test_old_impersonation_adapter():
    result = impersonation_from_old_result(
        {
            "global_brand_intelligence": {
                "impersonation_detected": True,
                "similarity_score": 97,
                "matched_brand": "Google",
            }
        }
    )

    assert result[
        "detected"
    ]

    assert result[
        "similarity"
    ] == 0.97

    assert (
        result[
            "claimed_brand"
        ]
        == "Google"
    )
