from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PlatformRelationship:
    suffix: str
    provider: str
    relationship_type: str

    can_be_official_root_domain: bool
    user_generated: bool
    shared_platform: bool

    notes: str


PLATFORMS = [
    # Code / developer platforms
    PlatformRelationship(
        suffix="github.com",
        provider="GitHub",
        relationship_type="code_repository",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes=(
            "Organization/user/project profiles hosted by GitHub "
            "must not transfer github.com ownership."
        ),
    ),

    PlatformRelationship(
        suffix="gitlab.com",
        provider="GitLab",
        relationship_type="code_repository",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes=(
            "GitLab organization/project profile."
        ),
    ),

    # Social
    PlatformRelationship(
        suffix="linkedin.com",
        provider="LinkedIn",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Professional organization/profile page.",
    ),

    PlatformRelationship(
        suffix="facebook.com",
        provider="Meta",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Facebook organization/profile page.",
    ),

    PlatformRelationship(
        suffix="instagram.com",
        provider="Meta",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Instagram organization/profile page.",
    ),

    PlatformRelationship(
        suffix="x.com",
        provider="X",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="X account/profile.",
    ),

    PlatformRelationship(
        suffix="twitter.com",
        provider="X",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Legacy Twitter account/profile.",
    ),

    PlatformRelationship(
        suffix="youtube.com",
        provider="YouTube",
        relationship_type="social_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="YouTube channel/profile.",
    ),

    # Publishing / blogging
    PlatformRelationship(
        suffix="medium.com",
        provider="Medium",
        relationship_type="blog_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Medium publication/profile.",
    ),

    PlatformRelationship(
        suffix="blogspot.com",
        provider="Google",
        relationship_type="blog_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Blogger-hosted publication.",
    ),

    PlatformRelationship(
        suffix="wordpress.com",
        provider="Automattic",
        relationship_type="blog_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="WordPress.com hosted site.",
    ),

    # Research / academic profiles
    PlatformRelationship(
        suffix="researchgate.net",
        provider="ResearchGate",
        relationship_type="research_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Research profile or institution page.",
    ),

    PlatformRelationship(
        suffix="academia.edu",
        provider="Academia.edu",
        relationship_type="research_profile",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Research profile.",
    ),

    # Shared hosting
    PlatformRelationship(
        suffix="github.io",
        provider="GitHub",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="GitHub Pages tenant.",
    ),

    PlatformRelationship(
        suffix="pages.dev",
        provider="Cloudflare",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Cloudflare Pages tenant.",
    ),

    PlatformRelationship(
        suffix="workers.dev",
        provider="Cloudflare",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Cloudflare Workers tenant.",
    ),

    PlatformRelationship(
        suffix="vercel.app",
        provider="Vercel",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Vercel deployment.",
    ),

    PlatformRelationship(
        suffix="netlify.app",
        provider="Netlify",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Netlify deployment.",
    ),

    PlatformRelationship(
        suffix="weebly.com",
        provider="Weebly",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Weebly hosted site.",
    ),

    PlatformRelationship(
        suffix="wixsite.com",
        provider="Wix",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Wix hosted site.",
    ),

    PlatformRelationship(
        suffix="webflow.io",
        provider="Webflow",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Webflow hosted site.",
    ),

    PlatformRelationship(
        suffix="firebaseapp.com",
        provider="Google",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Firebase application hosting.",
    ),

    PlatformRelationship(
        suffix="web.app",
        provider="Google",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Firebase Hosting tenant.",
    ),

    PlatformRelationship(
        suffix="appspot.com",
        provider="Google",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Google App Engine tenant.",
    ),

    PlatformRelationship(
        suffix="run.app",
        provider="Google",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Google Cloud Run deployment.",
    ),

    PlatformRelationship(
        suffix="azurewebsites.net",
        provider="Microsoft",
        relationship_type="user_generated_hosting",
        can_be_official_root_domain=False,
        user_generated=True,
        shared_platform=True,
        notes="Azure App Service tenant.",
    ),
]


def platform_records() -> list[dict[str, Any]]:
    return [
        {
            "suffix": item.suffix,
            "provider": item.provider,
            "relationship_type": (
                item.relationship_type
            ),
            "can_be_official_root_domain": (
                item.can_be_official_root_domain
            ),
            "user_generated": item.user_generated,
            "shared_platform": item.shared_platform,
            "notes": item.notes,
        }
        for item in PLATFORMS
    ]
