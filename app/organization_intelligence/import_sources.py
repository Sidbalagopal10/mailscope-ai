from __future__ import annotations

import argparse
import json

from app.organization_intelligence.sources.cisa_dotgov import (
    import_dataset as import_cisa_dotgov,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Download and import authoritative "
            "organization-domain datasets."
        )
    )

    parser.add_argument(
        "source",
        choices=[
            "cisa-dotgov",
        ],
    )

    parser.add_argument(
        "--force-download",
        action="store_true",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    return parser


def main() -> None:
    parser = build_parser()

    arguments = parser.parse_args()

    if arguments.source == "cisa-dotgov":
        result = import_cisa_dotgov(
            force_download=(
                arguments.force_download
            ),
            limit=arguments.limit,
        )

    else:
        raise SystemExit(
            "Unsupported source."
        )

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
