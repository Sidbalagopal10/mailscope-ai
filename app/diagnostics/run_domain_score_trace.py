from __future__ import annotations

import argparse
from pprint import pprint

from app.diagnostics.domain_score_trace import (
    DEFAULT_DOMAINS,
    run_domain_audit,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Trace score contributions for official domains."
        )
    )

    parser.add_argument(
        "domains",
        nargs="*",
        default=DEFAULT_DOMAINS,
    )

    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help=(
            "Refresh external intelligence. "
            "Avoid this when testing many domains."
        ),
    )

    args = parser.parse_args()

    report = run_domain_audit(
        domains=args.domains,
        force_refresh=(
            args.force_refresh
        ),
    )

    print()
    print("=" * 90)
    print("DOMAIN SCORE TRACE")
    print("=" * 90)

    for trace in report[
        "domains"
    ]:
        comparison = trace[
            "comparison"
        ]

        print()
        print("-" * 90)
        print(
            "Domain:",
            trace[
                "input"
            ],
        )

        print(
            "Base score:",
            comparison[
                "base_final_score"
            ],
        )

        print(
            "Enriched score:",
            comparison[
                "enriched_final_score"
            ],
        )

        print(
            "Wrapper delta:",
            comparison[
                "enriched_wrapper_delta"
            ],
        )

        print(
            "Base classification:",
            comparison[
                "base_classification"
            ],
        )

        print(
            "Enriched classification:",
            comparison[
                "enriched_classification"
            ],
        )

        if trace[
            "base_error"
        ]:
            print(
                "Base error:",
                trace[
                    "base_error"
                ],
            )

        if trace[
            "enriched_error"
        ]:
            print(
                "Enriched error:",
                trace[
                    "enriched_error"
                ],
            )

        print()
        print(
            "Base module summary:"
        )

        pprint(
            trace[
                "base_summary"
            ],
            sort_dicts=False,
        )

        print()
        print(
            "Score-like values:"
        )

        for finding in trace[
            "base_relevant_values"
        ]:
            if finding[
                "kind"
            ] == "numeric_signal":
                print(
                    " ",
                    finding[
                        "path"
                    ],
                    "=",
                    finding[
                        "value"
                    ],
                )

    print()
    print("=" * 90)
    print(
        "Full report saved to:"
    )
    print(
        "data/diagnostics/latest_domain_score_trace.json"
    )


if __name__ == "__main__":
    main()
