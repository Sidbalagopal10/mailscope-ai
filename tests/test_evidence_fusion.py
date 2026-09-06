from __future__ import annotations

from app.evidence_fusion.adapters import (
    domain_age_evidence,
    identity_evidence,
    impersonation_evidence,
    threatfox_evidence,
    virustotal_evidence,
)
from app.evidence_fusion.engine import (
    fuse_evidence,
)
from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)


def test_google_style_false_threatfox_match_is_filtered():
    evidence = []

    evidence += identity_evidence(
        {
            "identity_state": "verified",
            "confidence": 0.99,
            "entity": {
                "name": "Google"
            },
        }
    )

    evidence += threatfox_evidence(
        matched=True,
        exact_relevance=False,
        confidence=1.0,
        ioc_count=26,
    )

    evidence += virustotal_evidence(
        malicious=0,
        suspicious=0,
        harmless=90,
    )

    result = fuse_evidence(
        evidence,
        identity_state="verified",
    )

    assert result.risk_score < 35
    assert result.risk_level == "low"
    assert (
        "irrelevant_reputation_evidence_filtered"
        in result.safeguards_triggered
    )


def test_single_weak_vt_detection_cannot_make_official_domain_high():
    evidence = []

    evidence += identity_evidence(
        {
            "identity_state": "verified",
            "confidence": 0.98,
            "entity": {
                "name": "NVIDIA"
            },
        }
    )

    evidence += virustotal_evidence(
        malicious=1,
        suspicious=0,
    )

    result = fuse_evidence(
        evidence,
        identity_state="verified",
    )

    assert result.risk_score < 35


def test_unknown_domain_is_not_malicious_by_default():
    evidence = identity_evidence(
        {
            "identity_state": "unknown",
            "confidence": 0.0,
        }
    )

    result = fuse_evidence(
        evidence,
        identity_state="unknown",
    )

    assert result.risk_score == 0
    assert result.risk_level == "low"


def test_new_lookalike_gets_high_when_corroborated():
    evidence = []

    evidence += identity_evidence(
        {
            "identity_state": "unknown",
            "confidence": 0.0,
        }
    )

    evidence += impersonation_evidence(
        detected=True,
        similarity=0.96,
        claimed_brand="Microsoft",
    )

    evidence += domain_age_evidence(
        age_days=2,
    )

    evidence += virustotal_evidence(
        malicious=6,
        suspicious=2,
    )

    result = fuse_evidence(
        evidence,
        identity_state="unknown",
    )

    assert result.risk_score >= 60
    assert (
        result.corroborating_malicious_families
        >= 2
    )


def test_one_source_cannot_force_high():
    evidence = [
        Evidence(
            source="single_feed",
            family=EvidenceFamily.REPUTATION,
            direction=EvidenceDirection.MALICIOUS,
            strength=EvidenceStrength.STRONG,
            confidence=0.99,
            reason="One reputation source flagged the domain.",
            independent_group="single_feed",
        )
    ]

    result = fuse_evidence(
        evidence,
        identity_state="unknown",
    )

    assert result.risk_score < 60


def test_verified_domain_can_still_be_high_if_compromised():
    evidence = []

    evidence += identity_evidence(
        {
            "identity_state": "verified",
            "confidence": 0.99,
            "entity": {
                "name": "Example Corporation"
            },
        }
    )

    evidence += [
        Evidence(
            source="VirusTotal",
            family=EvidenceFamily.REPUTATION,
            direction=EvidenceDirection.MALICIOUS,
            strength=EvidenceStrength.STRONG,
            confidence=0.98,
            reason=(
                "Multiple engines report the exact URL as malicious."
            ),
            independent_group="virustotal",
        ),
        Evidence(
            source="credential_intent",
            family=EvidenceFamily.CONTENT,
            direction=EvidenceDirection.MALICIOUS,
            strength=EvidenceStrength.STRONG,
            confidence=0.95,
            reason=(
                "The page requests account credentials."
            ),
            independent_group="content_model",
        ),
        Evidence(
            source="redirect_analysis",
            family=EvidenceFamily.BEHAVIOR,
            direction=EvidenceDirection.MALICIOUS,
            strength=EvidenceStrength.MODERATE,
            confidence=0.90,
            reason=(
                "The URL redirects through suspicious infrastructure."
            ),
            independent_group="redirect_analysis",
        ),
    ]

    result = fuse_evidence(
        evidence,
        identity_state="verified",
    )

    assert result.risk_score >= 60
