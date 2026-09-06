from __future__ import annotations

from app.brand_intelligence import (
    global_brand_index as brands,
)


def create_test_index(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        brands,
        "DATABASE_PATH",
        tmp_path / "brands.db",
    )

    brands.upsert_brand(
        brand_name="Apple",
        aliases={
            "apple",
        },
        domains=[
            "apple.com",
        ],
        entity_type="corporation",
        country_code="US",
        organization_id=None,
        source="test",
        identity_confidence=98,
        identity_state=(
            "VERIFIED_ESTABLISHED"
        ),
        security_state="NEUTRAL",
    )

    brands.upsert_brand(
        brand_name="LinkedIn",
        aliases={
            "linkedin",
        },
        domains=[
            "linkedin.com",
        ],
        entity_type="corporation",
        country_code="US",
        organization_id=2,
        source="test",
        identity_confidence=98,
        identity_state=(
            "VERIFIED_ESTABLISHED"
        ),
        security_state="NEUTRAL",
    )


def test_official_domain_not_impersonation(
    tmp_path,
    monkeypatch,
):
    create_test_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "www.apple.com"
        )
    )

    assert not result[
        "impersonation_detected"
    ]


def test_apple_typo_detected(
    tmp_path,
    monkeypatch,
):
    create_test_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "applee.com"
        )
    )

    assert result[
        "impersonation_detected"
    ]

    assert (
        result[
            "strongest_finding"
        ][
            "brand_name"
        ]
        == "Apple"
    )


def test_linkedin_confusable_detected(
    tmp_path,
    monkeypatch,
):
    create_test_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "linkedln-login.example.com"
        )
    )

    assert result[
        "impersonation_detected"
    ]


def test_unrelated_unknown_domain_is_neutral(
    tmp_path,
    monkeypatch,
):
    create_test_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "small-university.so"
        )
    )

    assert not result[
        "impersonation_detected"
    ]

    assert (
        result[
            "risk_adjustment"
        ]
        == 0
    )
