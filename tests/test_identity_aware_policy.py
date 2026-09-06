from __future__ import annotations

from app.evidence_fusion.identity_aware_policy import (
    evaluate_identity_aware_candidate,
)


def test_unknown_alone_is_neutral():
    result = evaluate_identity_aware_candidate(
        url="https://unknown.example/",
        severity=0.0,
        is_suspicious=False,
        legacy_reasons=[],
        identity_state="unknown",
    )

    assert result.escalation_applied is False
    assert result.candidate_suspicious is False
    assert result.candidate_severity == 0.0


def test_unknown_brand_login_escalates():
    result = evaluate_identity_aware_candidate(
        url="https://microsoft-login.example/",
        severity=3.4,
        is_suspicious=False,
        legacy_reasons=[
            "Suspicious terms detected: login",
            "Possible brand impersonation: microsoft",
        ],
        identity_state="unknown",
    )

    assert result.escalation_applied is True
    assert result.candidate_suspicious is True
    assert result.candidate_severity >= 6.0


def test_unknown_brand_on_shared_host_escalates():
    result = evaluate_identity_aware_candidate(
        url="https://google-auth.vercel.app/",
        severity=3.0,
        is_suspicious=False,
        legacy_reasons=[
            "Possible brand impersonation: google",
        ],
        identity_state="unknown",
    )

    assert result.shared_host_detected is True
    assert result.escalation_applied is True
    assert result.candidate_suspicious is True


def test_identity_conflict_does_not_escalate():
    result = evaluate_identity_aware_candidate(
        url="https://nmu.edu.pk/",
        severity=0.0,
        is_suspicious=False,
        legacy_reasons=[],
        identity_state="conflicting",
    )

    assert result.escalation_applied is False
    assert result.candidate_suspicious is False


def test_verified_domain_not_blanket_allowlisted():
    result = evaluate_identity_aware_candidate(
        url="https://example.org/",
        severity=8.5,
        is_suspicious=True,
        legacy_reasons=[
            "Independent malware evidence"
        ],
        identity_state="verified",
    )

    assert result.candidate_suspicious is True
    assert result.candidate_severity == 8.5
