from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class HostingProvider:
    provider: str
    platform: str
    suffix: str

    category: str
    hosting_type: str

    user_generated: bool
    shared_infrastructure: bool

    owner_verified: bool = True

    risk_effect: str = "neutral"
    requires_corroboration: bool = True

    source_type: str = "provider_fingerprint"


PROVIDERS = [
    HostingProvider(
        provider="GitHub",
        platform="GitHub Pages",
        suffix="github.io",
        category="user_generated_hosting",
        hosting_type="static_site_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Cloudflare",
        platform="Cloudflare Pages",
        suffix="pages.dev",
        category="user_generated_hosting",
        hosting_type="static_site_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Cloudflare",
        platform="Cloudflare Workers",
        suffix="workers.dev",
        category="user_generated_hosting",
        hosting_type="serverless",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Vercel",
        platform="Vercel",
        suffix="vercel.app",
        category="user_generated_hosting",
        hosting_type="application_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Netlify",
        platform="Netlify",
        suffix="netlify.app",
        category="user_generated_hosting",
        hosting_type="static_site_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Blogger",
        suffix="blogspot.com",
        category="user_generated_hosting",
        hosting_type="blog_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Weebly",
        platform="Weebly",
        suffix="weebly.com",
        category="user_generated_hosting",
        hosting_type="website_builder",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Firebase Hosting",
        suffix="web.app",
        category="user_generated_hosting",
        hosting_type="static_site_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Firebase Hosting",
        suffix="firebaseapp.com",
        category="user_generated_hosting",
        hosting_type="application_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Google Cloud Run",
        suffix="run.app",
        category="cloud_platform",
        hosting_type="serverless",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Google App Engine",
        suffix="appspot.com",
        category="cloud_platform",
        hosting_type="application_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Microsoft",
        platform="Azure App Service",
        suffix="azurewebsites.net",
        category="cloud_platform",
        hosting_type="application_hosting",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Amazon Web Services",
        platform="Amazon S3",
        suffix="s3.amazonaws.com",
        category="cloud_platform",
        hosting_type="object_storage",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Microsoft",
        platform="Azure Blob Storage",
        suffix="blob.core.windows.net",
        category="cloud_platform",
        hosting_type="object_storage",
        user_generated=True,
        shared_infrastructure=True,
    ),

    HostingProvider(
        provider="Google",
        platform="Google Cloud Storage",
        suffix="storage.googleapis.com",
        category="cloud_platform",
        hosting_type="object_storage",
        user_generated=True,
        shared_infrastructure=True,
    ),
]


def provider_dicts() -> list[dict[str, Any]]:
    return [
        asdict(
            provider
        )
        for provider in PROVIDERS
    ]
