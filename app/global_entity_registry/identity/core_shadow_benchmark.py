from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from app.global_entity_registry.database import (
    using_database,
)
from app.global_entity_registry.identity.live_detector_adapter import (
    run_live_detector,
)
from app.global_entity_registry.identity.shadow import (
    shadow_identity_summary,
)


REHEARSAL_DATABASE = Path(
    "data/rehearsal/"
    "clean_registry_rehearsal.db"
)


CASES = [
    # -------------------------------------------------
    # Independently verified organizations
    # -------------------------------------------------
    {
        "category": "verified_legitimate",
        "expected": "legitimate",
        "url": (
            "https://research.microsoft.com/"
        ),
    },

    {
        "category": "verified_legitimate",
        "expected": "legitimate",
        "url": (
            "https://sinica.edu.tw/"
        ),
    },

    {
        "category": "verified_legitimate",
        "expected": "legitimate",
        "url": (
            "https://jpmc.com.pk/"
        ),
    },

    {
        "category": "verified_legitimate",
        "expected": "legitimate",
        "url": (
            "https://ucsfbenioffchildrens.org/"
        ),
    },

    # -------------------------------------------------
    # Legitimate shared organizational infrastructure
    # -------------------------------------------------
    {
        "category": "shared_legitimate",
        "expected": "legitimate",
        "url": "https://nyc.gov/",
    },

    {
        "category": "shared_legitimate",
        "expected": "legitimate",
        "url": "https://va.gov/",
    },

    {
        "category": "shared_legitimate",
        "expected": "legitimate",
        "url": "https://who.int/",
    },

    {
        "category": "shared_legitimate",
        "expected": "legitimate",
        "url": (
            "https://healthy."
            "kaiserpermanente.org/"
        ),
    },

    # -------------------------------------------------
    # Registry disagreement.
    #
    # These are NOT labeled phishing.
    # -------------------------------------------------
    {
        "category": "identity_conflict",
        "expected": "identity_uncertain",
        "url": "https://nmu.edu.pk/",
    },

    {
        "category": "identity_conflict",
        "expected": "identity_uncertain",
        "url": "https://nmch.edu.pk/",
    },

    {
        "category": "identity_conflict",
        "expected": "identity_uncertain",
        "url": "https://usf.edu.br/",
    },

    # -------------------------------------------------
    # Unknown neutral domain.
    #
    # Unknown must NOT automatically become malicious.
    # .example is reserved for examples and will not
    # resolve on the public Internet.
    # -------------------------------------------------
    {
        "category": "unknown_neutral",
        "expected": "unknown",
        "url": (
            "https://unknown-startup.example/"
        ),
    },

    # -------------------------------------------------
    # Brand-like names on unknown domains.
    #
    # Identity alone must still say UNKNOWN.
    # The phishing detector may independently find
    # impersonation signals.
    # -------------------------------------------------
    {
        "category": "lookalike",
        "expected": "suspicious_pattern",
        "url": (
            "https://microsoft-login.example/"
        ),
    },

    {
        "category": "lookalike",
        "expected": "suspicious_pattern",
        "url": (
            "https://google-secure.example/"
        ),
    },

    # -------------------------------------------------
    # User-generated hosting lookalikes.
    # -------------------------------------------------
    {
        "category": "shared_host_lookalike",
        "expected": "suspicious_pattern",
        "url": (
            "https://microsoft-login.pages.dev/"
        ),
    },

    {
        "category": "shared_host_lookalike",
        "expected": "suspicious_pattern",
        "url": (
            "https://google-auth.vercel.app/"
        ),
    },
]


def run_benchmark() -> dict[str, Any]:
    rows = []

    for number, case in enumerate(
        CASES,
        start=1,
    ):
        url = case[
            "url"
        ]

        print()
        print(
            f"[{number}/{len(CASES)}] "
            f"{url}"
        )

        # -----------------------------
        # CURRENT detector
        # -----------------------------
        try:
            legacy = (
                run_live_detector(
                    url
                )
            )

        except Exception as error:
            legacy = {
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                )
            }

        # -----------------------------
        # NEW identity engine
        #
        # Rehearsal DB ONLY.
        # -----------------------------
        try:
            with using_database(
                REHEARSAL_DATABASE
            ):
                identity = (
                    shadow_identity_summary(
                        url
                    )
                )

        except Exception as error:
            identity = {
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                )
            }

        row = {
            "category": (
                case[
                    "category"
                ]
            ),

            "expected": (
                case[
                    "expected"
                ]
            ),

            "url": url,

            "legacy": legacy,

            "identity": identity,
        }

        # -----------------------------
        # Diagnostic flags
        # -----------------------------
        flags = []

        if (
            legacy.get(
                "is_suspicious"
            )
            is True
            and identity.get(
                "identity_state"
            )
            == "verified"
        ):
            flags.append(
                "possible_false_positive_on_verified_identity"
            )

        if (
            legacy.get(
                "is_suspicious"
            )
            is True
            and identity.get(
                "identity_state"
            )
            == "supported"
        ):
            flags.append(
                "possible_false_positive_on_supported_identity"
            )

        if (
            identity.get(
                "identity_state"
            )
            == "unknown"
        ):
            flags.append(
                "identity_unknown_neutral"
            )

        if (
            identity.get(
                "identity_state"
            )
            == "conflicting"
        ):
            flags.append(
                "identity_sources_conflict"
            )

        row[
            "diagnostic_flags"
        ] = flags

        rows.append(
            row
        )

    # ---------------------------------
    # Summary
    # ---------------------------------
    categories = Counter(
        row[
            "category"
        ]
        for row in rows
    )

    legacy_suspicious = sum(
        1
        for row in rows
        if row.get(
            "legacy",
            {}
        ).get(
            "is_suspicious"
        )
        is True
    )

    verified_flagged = sum(
        1
        for row in rows
        if (
            row.get(
                "identity",
                {}
            ).get(
                "identity_state"
            )
            == "verified"
            and row.get(
                "legacy",
                {}
            ).get(
                "is_suspicious"
            )
            is True
        )
    )

    supported_flagged = sum(
        1
        for row in rows
        if (
            row.get(
                "identity",
                {}
            ).get(
                "identity_state"
            )
            == "supported"
            and row.get(
                "legacy",
                {}
            ).get(
                "is_suspicious"
            )
            is True
        )
    )

    return {
        "mode": "shadow_only",

        "production_changed": False,

        "case_count": len(
            rows
        ),

        "category_counts": dict(
            categories
        ),

        "legacy_suspicious_count": (
            legacy_suspicious
        ),

        "verified_identity_flagged_by_legacy": (
            verified_flagged
        ),

        "supported_identity_flagged_by_legacy": (
            supported_flagged
        ),

        "rows": rows,
    }


def save_report(
    report: dict[str, Any],
) -> Path:
    output = Path(
        "data/shadow_evaluation/"
        "core_engine_freeze_shadow.json"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return output
