from __future__ import annotations

import argparse

from app.shadow_evaluation.evaluator import (
    run_shadow_suite,
)


DEFAULT_CASES = [
    "https://google.com/",
    "https://microsoft.com/",
    "https://apple.com/",
    "https://nvidia.com/",
    "https://github.com/",
    "https://gwu.edu/",
    "https://python.org/",
    "https://bbc.co.uk/",
    "https://unknown-startup.example/",
    "https://goog1e-login.example/",
    "https://microsoft-login.example/",
    "https://nvidia-secure.example/",
    "https://github-auth.example/",
]


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "values",
        nargs="*",
        default=DEFAULT_CASES,
    )

    parser.add_argument(
        "--force-refresh",
        action="store_true",
    )

    args = parser.parse_args()

    report = run_shadow_suite(
        args.values,
        force_refresh=args.force_refresh,
    )

    print()
    print(
        f"{'INPUT':<39}"
        f"{'OLD':>8}"
        f"{'NEW':>8}"
        f"{'IDENTITY':>14}"
        f"{'OLD RISK':>13}"
        f"{'NEW RISK':>13}"
    )

    print(
        "-" * 95
    )

    for row in report[
        "results"
    ]:
        if "error" in row:
            print(
                f"{row['input']:<39}"
                f"{'ERROR':>8}"
            )

            print(
                "  ",
                row[
                    "error"
                ],
            )

            continue

        print(
            f"{row['input']:<39}"
            f"{str(row['old']['score']):>8}"
            f"{str(row['new']['score']):>8}"
            f"{str(row['new']['identity_state']):>14}"
            f"{str(row['old']['risk_level']):>13}"
            f"{str(row['new']['risk_level']):>13}"
        )

        safeguards = row[
            "new"
        ][
            "safeguards"
        ]

        if safeguards:
            print(
                "  safeguards:",
                ", ".join(
                    safeguards
                ),
            )

    print()
    print(
        "Full report:"
    )

    print(
        "data/shadow_evaluation/"
        "latest_shadow_report.json"
    )


if __name__ == "__main__":
    main()
