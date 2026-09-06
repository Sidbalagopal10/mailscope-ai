from __future__ import annotations

import argparse
from pathlib import Path
from pprint import pprint

from app.global_entity_registry.ingestors.wikidata_dump_extractor import (
    extract_dump,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Stream a Wikidata JSON dump and import "
            "entities containing P856 official websites."
        )
    )

    parser.add_argument(
        "dump",
        type=Path,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=10_000,
    )

    parser.add_argument(
        "--resume",
        action="store_true",
    )

    args = parser.parse_args()

    result = extract_dump(
        args.dump,
        limit=args.limit,
        checkpoint_every=(
            args.checkpoint_every
        ),
        resume=args.resume,
    )

    print()
    print("=" * 70)
    print("WIKIDATA EXTRACTION COMPLETE")
    print("=" * 70)

    pprint(
        result,
        sort_dicts=False,
    )


if __name__ == "__main__":
    main()
