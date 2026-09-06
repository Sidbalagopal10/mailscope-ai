from __future__ import annotations

from app.website_relationships.classifier import (
    classify_website_relationship,
)


def test_github_profile_not_official_domain():
    result = classify_website_relationship(
        "https://github.com/CICE-Consortium"
    )

    assert (
        result[
            "relationship_type"
        ]
        == "code_repository"
    )

    assert (
        result[
            "eligible_as_official_domain"
        ]
        is False
    )


def test_github_pages_not_official_root():
    result = classify_website_relationship(
        "https://example.github.io/"
    )

    assert (
        result[
            "relationship_type"
        ]
        == "user_generated_hosting"
    )

    assert (
        result[
            "eligible_as_official_domain"
        ]
        is False
    )


def test_linkedin_not_official_domain():
    result = classify_website_relationship(
        "https://linkedin.com/company/example"
    )

    assert (
        result[
            "relationship_type"
        ]
        == "social_profile"
    )


def test_vercel_not_official_domain():
    result = classify_website_relationship(
        "https://example.vercel.app/"
    )

    assert (
        result[
            "eligible_as_official_domain"
        ]
        is False
    )


def test_regular_domain_remains_candidate():
    result = classify_website_relationship(
        "https://example-corporation.com/"
    )

    assert (
        result[
            "relationship_type"
        ]
        == "official_website_candidate"
    )

    assert (
        result[
            "eligible_as_official_domain"
        ]
        is True
    )


def test_microsoft_root_remains_candidate():
    result = classify_website_relationship(
        "https://microsoft.com/"
    )

    assert (
        result[
            "eligible_as_official_domain"
        ]
        is True
    )
