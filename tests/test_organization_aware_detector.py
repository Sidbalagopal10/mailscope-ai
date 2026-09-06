from app.detection.organization_aware_detector import (
    analyze_url_with_organization_intelligence,
)
from app.organization_intelligence import (
    store,
)


def add_verified_organization(
    *,
    domain: str,
    legal_name: str,
    security_state: str = "NEUTRAL",
):
    return store.upsert_organization_domain(
        legal_name=legal_name,
        entity_type="university",
        domain=domain,
        source_name="Test Education Registry",
        source_type="education_registry",
        source_record_id=domain,
        authoritative_source=True,
        country_code="US",
        identity_state="VERIFIED_ESTABLISHED",
        security_state=security_state,
        identity_confidence=96,
        security_confidence=80,
    )


def test_verified_clean_university_reduces_uncertainty(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    add_verified_organization(
        domain="example.edu",
        legal_name="Example University",
    )

    result = (
        analyze_url_with_organization_intelligence(
            "https://www.example.edu/admissions"
        )
    )

    assert result[
        "organization_intelligence"
    ][
        "matched"
    ]

    assert result[
        "final_score"
    ] < 20

    assert (
        result["classification"]
        == "likely_legitimate"
    )


def test_unknown_domain_receives_no_adjustment(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    result = (
        analyze_url_with_organization_intelligence(
            "https://unknown-school.example/admissions"
        )
    )

    intelligence = result[
        "organization_intelligence"
    ]

    assert not intelligence[
        "matched"
    ]

    assert (
        intelligence[
            "applied_score_adjustment"
        ]
        == 0
    )


def test_verified_identity_does_not_override_impersonation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    add_verified_organization(
        domain="example.com",
        legal_name="Example Corporation",
    )

    result = (
        analyze_url_with_organization_intelligence(
            "https://linkedln-login.example.com/verify"
        )
    )

    assert result[
        "organization_intelligence"
    ][
        "adjustment_blocked"
    ]

    assert result[
        "is_phishing"
    ]


def test_compromised_legitimate_domain_increases_risk(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    add_verified_organization(
        domain="compromised.edu",
        legal_name="Compromised University",
        security_state="COMPROMISED_LEGITIMATE",
    )

    result = (
        analyze_url_with_organization_intelligence(
            "https://compromised.edu/"
        )
    )

    intelligence = result[
        "organization_intelligence"
    ]

    assert (
        intelligence[
            "applied_score_adjustment"
        ]
        > 0
    )

    assert (
        result[
            "final_score"
        ]
        > result[
            "final_score_before_organization_intelligence"
        ]
    )
