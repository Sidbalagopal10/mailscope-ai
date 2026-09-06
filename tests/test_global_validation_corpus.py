from __future__ import annotations

from app.shadow_evaluation.validation_corpus import (
    mutate_label,
)


def test_mutation_creates_variants():
    values = mutate_label(
        "google"
    )

    assert values

    assert (
        "google"
        not in values
    )


def test_mutation_contains_login_variant():
    values = mutate_label(
        "microsoft"
    )

    assert (
        "microsoft-login"
        in values
    )
