from __future__ import annotations

from app.global_entity_registry.ingestion.domain_guard import (
    should_create_domain_identity,
)
from app.global_entity_registry.ingestion.website_policy import (
    evaluate_website_for_ingestion,
)


def test_regular_organization_domain_is_eligible():
    result = evaluate_website_for_ingestion(
        "https://example-corporation.com/"
    )

    assert (
        result.eligible_for_domain_identity
        is True
    )

    assert (
        result.relationship_type
        == "official_website_candidate"
    )


def test_github_repository_not_domain_identity():
    result = evaluate_website_for_ingestion(
        "https://github.com/CICE-Consortium"
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.preserve_as_relationship
        is True
    )

    assert (
        result.relationship_type
        == "code_repository"
    )


def test_linkedin_profile_not_domain_identity():
    assert (
        should_create_domain_identity(
            "https://linkedin.com/company/example"
        )
        is False
    )


def test_cloudflare_pages_not_domain_identity():
    result = evaluate_website_for_ingestion(
        "https://example.pages.dev/"
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.relationship_type
        == "user_generated_hosting"
    )


def test_vercel_not_domain_identity():
    assert (
        should_create_domain_identity(
            "https://example.vercel.app/"
        )
        is False
    )


def test_blogspot_not_domain_identity():
    result = evaluate_website_for_ingestion(
        "https://example.blogspot.com/"
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.relationship_type
        == "blog_profile"
    )


def test_microsoft_domain_remains_eligible():
    assert (
        should_create_domain_identity(
            "https://microsoft.com/"
        )
        is True
    )


def test_isro_domain_remains_eligible():
    assert (
        should_create_domain_identity(
            "https://www.isro.gov.in/"
        )
        is True
    )


def test_invalid_value_rejected():
    result = evaluate_website_for_ingestion(
        ""
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.preserve_as_relationship
        is False
    )
