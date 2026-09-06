from __future__ import annotations

from app.hosting_intelligence.corroboration import (
    shared_host_corroboration,
)
from app.hosting_intelligence.matcher import (
    identify_hosting,
)


def test_github_pages():
    result = identify_hosting(
        "https://example.github.io/"
    )

    assert result[
        "matched"
    ]

    assert (
        result[
            "provider"
        ]
        == "GitHub"
    )

    assert result[
        "user_generated"
    ]


def test_cloudflare_pages():
    result = identify_hosting(
        "https://example.pages.dev/"
    )

    assert result[
        "matched"
    ]

    assert (
        result[
            "provider"
        ]
        == "Cloudflare"
    )


def test_vercel():
    result = identify_hosting(
        "https://example.vercel.app/"
    )

    assert result[
        "matched"
    ]

    assert (
        result[
            "provider"
        ]
        == "Vercel"
    )


def test_netlify():
    result = identify_hosting(
        "https://example.netlify.app/"
    )

    assert result[
        "matched"
    ]

    assert (
        result[
            "provider"
        ]
        == "Netlify"
    )


def test_shared_host_is_neutral():
    result = identify_hosting(
        "https://example.pages.dev/"
    )

    assert (
        result[
            "risk_effect"
        ]
        == "neutral"
    )


def test_unknown_host():
    result = identify_hosting(
        "https://example.com/"
    )

    assert not result[
        "matched"
    ]


def test_brand_plus_login_on_shared_host():
    hosting = identify_hosting(
        "https://microsoft-login.pages.dev/"
    )

    evidence = (
        shared_host_corroboration(
            value=(
                "https://microsoft-login."
                "pages.dev/account/login"
            ),
            hosting=hosting,
            identity_state="unknown",
        )
    )

    assert evidence

    assert (
        evidence[
            0
        ].direction.value
        == "malicious"
    )


def test_shared_host_without_brand_is_not_malicious():
    hosting = identify_hosting(
        "https://my-cooking-blog.pages.dev/"
    )

    evidence = (
        shared_host_corroboration(
            value=(
                "https://my-cooking-blog."
                "pages.dev/recipes"
            ),
            hosting=hosting,
            identity_state="unknown",
        )
    )

    assert (
        evidence
        == []
    )
