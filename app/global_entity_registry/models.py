from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceEvidence:
    source_name: str

    source_record_id: str | None = None
    source_url: str | None = None

    evidence_type: str = "unknown"

    confidence: float = 0.50
    authoritative: bool = False

    observed_at: str | None = None

    raw_reference: str | None = None


@dataclass
class WebsiteRelationship:
    """
    Semantic relationship between an organization and a URL/hostname.

    Examples:

    microsoft.com
        -> official_website_candidate

    github.com/example
        -> code_repository

    linkedin.com/company/example
        -> social_profile

    example.pages.dev
        -> user_generated_hosting

    The object itself does NOT prove ownership.
    """

    original_value: str

    hostname: str

    relationship_type: str

    eligible_for_domain_identity: bool

    preserve_as_relationship: bool = True

    provider: str | None = None
    platform_suffix: str | None = None

    confidence: float = 0.50

    source_name: str | None = None
    source_record_id: str | None = None

    reason: str | None = None


@dataclass
class EntityRecord:
    canonical_name: str

    entity_type: str | None = None

    country_code: str | None = None
    country_name: str | None = None
    continent: str | None = None

    status: str = "active"

    aliases: list[str] = field(
        default_factory=list
    )

    # -------------------------------------------------
    # LEGACY FIELD
    #
    # Kept temporarily so the existing repository and
    # importers continue working while we migrate.
    # -------------------------------------------------

    domains: list[str] = field(
        default_factory=list
    )

    # -------------------------------------------------
    # NEW STRUCTURED WEBSITE SEMANTICS
    # -------------------------------------------------

    website_relationships: list[
        WebsiteRelationship
    ] = field(
        default_factory=list
    )

    external_ids: dict[
        str,
        str,
    ] = field(
        default_factory=dict
    )

    evidence: dict[
        str,
        list[SourceEvidence],
    ] = field(
        default_factory=dict
    )
