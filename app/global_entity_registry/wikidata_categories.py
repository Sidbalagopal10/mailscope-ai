from __future__ import annotations

from typing import Any


# High-value Wikidata instance/subclass categories.
#
# This is deliberately broader than ROR.
# Unknown P31 classes are not discarded if P856 exists;
# they can enter the registry as "unclassified".
CATEGORY_QIDS: dict[str, set[str]] = {
    "company": {
        "Q4830453",      # business
        "Q783794",       # company
        "Q6881511",      # enterprise
        "Q891723",       # public company
        "Q167037",       # corporation
    },

    "education": {
        "Q3918",         # university
        "Q875538",       # public university
        "Q15936437",     # research university
        "Q189004",       # college
        "Q3914",         # school
        "Q31855",        # research institute
        "Q4671277",      # academic institution
    },

    "healthcare": {
        "Q16917",        # hospital
        "Q1774898",      # clinic
        "Q4287745",      # medical organization
        "Q31207",        # health care
    },

    "government": {
        "Q327333",       # government agency
        "Q2659904",      # government organization
        "Q43229",        # organization
        "Q7210356",      # political organization
    },

    "bank_finance": {
        "Q22687",        # bank
        "Q837171",       # financial services
        "Q4830453",      # business
        "Q6881511",      # enterprise
    },

    "retail": {
        "Q126793",       # retail
        "Q4830453",
    },

    "entertainment_media": {
        "Q11033",        # mass media
        "Q3624078",      # sovereign? keep broad mappings conservative
        "Q18127",        # record label
        "Q1762059",      # film production company
        "Q2085381",      # publisher
    },

    "sports": {
        "Q4438121",      # sports organization
        "Q847017",       # sports club
        "Q476028",       # association football club
    },

    "culture": {
        "Q33506",        # museum
        "Q207694",       # art museum
        "Q132241",       # cultural institution
        "Q166118",       # archive
        "Q7075",         # library
    },

    "tourism_hospitality": {
        "Q27686",        # hotel
        "Q11707",        # restaurant
        "Q15243209",     # tourism organization
    },

    "transport": {
        "Q46970",        # airline
        "Q249556",       # railway company
        "Q178512",       # public transport
        "Q740752",       # transport company
    },

    "space": {
        "Q26540",        # space agency
        "Q2133344",      # space organization
    },

    "defense": {
        "Q45295908",     # military organization
        "Q176799",       # military unit
    },

    "nonprofit": {
        "Q163740",       # nonprofit organization
        "Q79913",        # NGO
        "Q48204",        # voluntary association
        "Q157031",       # foundation
    },

    "telecom": {
        "Q1058914",      # telecommunications company
    },

    "energy": {
        "Q11396960",     # energy company
    },

    "wildlife_environment": {
        "Q178706",       # conservation organization
        "Q17377208",     # environmental organization
    },

    "professional_association": {
        "Q200764",       # professional association
        "Q327333",       # agency/org overlap
    },
}


def claim_entity_ids(
    entity: dict[str, Any],
    property_id: str,
) -> list[str]:
    claims = (
        entity.get(
            "claims",
            {},
        )
        or {}
    )

    statements = claims.get(
        property_id,
        [],
    )

    values: list[str] = []

    if not isinstance(
        statements,
        list,
    ):
        return values

    for statement in statements:
        if not isinstance(
            statement,
            dict,
        ):
            continue

        mainsnak = statement.get(
            "mainsnak",
            {},
        )

        datavalue = mainsnak.get(
            "datavalue",
            {},
        )

        value = datavalue.get(
            "value"
        )

        if not isinstance(
            value,
            dict,
        ):
            continue

        qid = value.get(
            "id"
        )

        if (
            isinstance(
                qid,
                str,
            )
            and qid.startswith(
                "Q"
            )
        ):
            values.append(
                qid
            )

    return list(
        dict.fromkeys(
            values
        )
    )


def classify_entity(
    entity: dict[str, Any],
) -> dict[str, Any]:
    p31_values = claim_entity_ids(
        entity,
        "P31",
    )

    matches: dict[
        str,
        list[str]
    ] = {}

    for category, qids in (
        CATEGORY_QIDS.items()
    ):
        category_matches = [
            qid
            for qid in p31_values
            if qid in qids
        ]

        if category_matches:
            matches[
                category
            ] = category_matches

    if not matches:
        primary = "unclassified"

    else:
        primary = next(
            iter(
                matches
            )
        )

    return {
        "primary_category": primary,
        "all_categories": list(
            matches
        ),
        "matched_type_qids": matches,
        "instance_of_qids": (
            p31_values
        ),
    }
