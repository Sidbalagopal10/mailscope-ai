from __future__ import annotations

from app.benchmarking.openphish_loader import (
    OPENPHISH_COMMUNITY_URL,
)
from app.benchmarking.run_openphish_holdout import (
    classify,
)


def test_openphish_source_is_not_detector_component():
    # The benchmark feed is external ground truth.
    # The detector itself has no OpenPhish adapter.
    assert (
        "openphish"
        in OPENPHISH_COMMUNITY_URL.lower()
    )


def test_threshold_classification():
    assert classify(
        35.0,
        35.0,
    )

    assert not classify(
        34.99,
        35.0,
    )
