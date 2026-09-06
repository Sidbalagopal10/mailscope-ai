from __future__ import annotations

from app.benchmarking.urlhaus_index import (
    normalize_url,
)
from app.evidence_fusion.adapters import (
    urlhaus_exact_evidence,
)
from app.evidence_fusion.engine import (
    fuse_evidence,
)


def test_normalization_removes_fragment():
    assert (
        normalize_url(
            "HTTP://Example.COM/path#fragment"
        )
        == "http://example.com/path"
    )


def test_urlhaus_exact_match_is_strong():
    evidence = urlhaus_exact_evidence(
        matched=True,
        match_type="exact_url",
    )

    assert len(
        evidence
    ) == 1

    assert (
        evidence[
            0
        ].exact_relevance
        is True
    )

    assert (
        evidence[
            0
        ].direction.value
        == "malicious"
    )


def test_non_exact_match_is_neutral():
    evidence = urlhaus_exact_evidence(
        matched=False,
        match_type="none",
    )

    assert (
        evidence[
            0
        ].direction.value
        == "neutral"
    )


def test_exact_feed_alone_does_not_break_general_single_source_rule():
    evidence = urlhaus_exact_evidence(
        matched=True,
        match_type="exact_url",
    )

    result = fuse_evidence(
        evidence,
        identity_state="unknown",
    )

    # Strong exact reputation evidence should raise risk,
    # but one non-critical source does not automatically
    # create a Critical verdict.
    assert result.risk_score > 0
    assert result.risk_score < 60
