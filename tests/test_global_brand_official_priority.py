from __future__ import annotations

from app.brand_intelligence import (
    global_brand_index as brands,
)


def prepare_index(
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
            "icloud",
        },
        domains=[
            "apple.com",
            "icloud.com",
        ],
        entity_type="corporation",
        country_code="US",
        organization_id=None,
        source="builtin",
        identity_confidence=98,
        identity_state="VERIFIED_ESTABLISHED",
        security_state="NEUTRAL",
    )

    # Deliberately insert a conflicting lower-quality alias.
    brands.upsert_brand(
        brand_name=(
            "Wichita State Applied Learning Center"
        ),
        aliases={
            "apple",
            "wichitastateappliedlearningcenter",
        },
        domains=[
            "wichita-example.edu",
        ],
        entity_type="university",
        country_code="US",
        organization_id=999,
        source="organization_intelligence",
        identity_confidence=90,
        identity_state="VERIFIED_ESTABLISHED",
        security_state="NEUTRAL",
    )


def test_apple_official_domain_overrides_conflicting_alias(
    tmp_path,
    monkeypatch,
):
    prepare_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "https://apple.com/"
        )
    )

    assert result[
        "official_domain_match"
    ]

    assert not result[
        "impersonation_detected"
    ]

    assert (
        result[
            "official_owner"
        ][
            "brand_name"
        ]
        == "Apple"
    )


def test_apple_subdomain_is_official(
    tmp_path,
    monkeypatch,
):
    prepare_index(
        tmp_path,
        monkeypatch,
    )

    result = (
        brands.analyze_brand_impersonation(
            "support.apple.com"
        )
    )

    assert result[
        "official_domain_match"
    ]

    assert not result[
        "impersonation_detected"
    ]


def test_apple_typo_still_detected(
    tmp_path,
    monkeypatch,
):
    prepare_index(
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


def test_microsoft_typo_still_detected(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        brands,
        "DATABASE_PATH",
        tmp_path / "microsoft.db",
    )

    brands.upsert_brand(
        brand_name="Microsoft",
        aliases={
            "microsoft",
        },
        domains=[
            "microsoft.com",
        ],
        entity_type="corporation",
        country_code="US",
        organization_id=None,
        source="builtin",
        identity_confidence=98,
        identity_state="VERIFIED_ESTABLISHED",
        security_state="NEUTRAL",
    )

    result = (
        brands.analyze_brand_impersonation(
            "microsooft.com"
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
        == "Microsoft"
    )
