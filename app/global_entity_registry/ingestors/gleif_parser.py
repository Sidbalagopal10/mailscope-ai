from __future__ import annotations

from typing import Any


def mapping(
    value: Any,
) -> dict[str, Any]:
    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def text(
    value: Any,
) -> str | None:
    if value is None:
        return None

    cleaned = str(
        value
    ).strip()

    return (
        cleaned
        if cleaned
        else None
    )


def address_fields(
    address: dict[str, Any] | None,
) -> dict[str, Any]:
    value = mapping(
        address
    )

    return {
        "country": text(
            value.get(
                "country"
            )
        ),
        "region": text(
            value.get(
                "region"
            )
        ),
        "city": text(
            value.get(
                "city"
            )
        ),
    }


def parse_lei_resource(
    resource: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(
        resource,
        dict,
    ):
        return None

    lei = text(
        resource.get(
            "id"
        )
    )

    attributes = mapping(
        resource.get(
            "attributes"
        )
    )

    entity = mapping(
        attributes.get(
            "entity"
        )
    )

    registration = mapping(
        attributes.get(
            "registration"
        )
    )

    legal_name = mapping(
        entity.get(
            "legalName"
        )
    )

    legal_name_value = text(
        legal_name.get(
            "name"
        )
    )

    if not lei or not legal_name_value:
        return None

    legal_address = (
        address_fields(
            entity.get(
                "legalAddress"
            )
        )
    )

    headquarters = (
        address_fields(
            entity.get(
                "headquartersAddress"
            )
        )
    )

    legal_form = mapping(
        entity.get(
            "legalForm"
        )
    )

    registration_authority = mapping(
        entity.get(
            "registeredAt"
        )
    )

    other_names: list[
        dict[str, str | None]
    ] = []

    for item in (
        entity.get(
            "otherNames",
            []
        )
        or []
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        name = text(
            item.get(
                "name"
            )
        )

        if not name:
            continue

        other_names.append(
            {
                "name": name,
                "type": (
                    text(
                        item.get(
                            "type"
                        )
                    )
                    or "other"
                ),
                "language": text(
                    item.get(
                        "language"
                    )
                ),
            }
        )

    return {
        "lei": lei.upper(),
        "legal_name": (
            legal_name_value
        ),
        "legal_name_language": (
            text(
                legal_name.get(
                    "language"
                )
            )
        ),
        "entity_status": text(
            entity.get(
                "status"
            )
        ),
        "jurisdiction": text(
            entity.get(
                "jurisdiction"
            )
        ),
        "legal_form_code": (
            text(
                legal_form.get(
                    "id"
                )
            )
        ),
        "registration_authority_id": (
            text(
                registration_authority.get(
                    "id"
                )
            )
        ),
        "registration_authority_entity_id": (
            text(
                entity.get(
                    "registeredAs"
                )
            )
        ),
        "headquarters_country": (
            headquarters[
                "country"
            ]
        ),
        "headquarters_region": (
            headquarters[
                "region"
            ]
        ),
        "headquarters_city": (
            headquarters[
                "city"
            ]
        ),
        "legal_address_country": (
            legal_address[
                "country"
            ]
        ),
        "legal_address_region": (
            legal_address[
                "region"
            ]
        ),
        "legal_address_city": (
            legal_address[
                "city"
            ]
        ),
        "initial_registration_date": (
            text(
                registration.get(
                    "initialRegistrationDate"
                )
            )
        ),
        "last_update_date": (
            text(
                registration.get(
                    "lastUpdateDate"
                )
            )
        ),
        "next_renewal_date": (
            text(
                registration.get(
                    "nextRenewalDate"
                )
            )
        ),
        "managing_lou": text(
            registration.get(
                "managingLou"
            )
        ),
        "other_names": other_names,
    }


def parse_response_records(
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    raw_data = payload.get(
        "data",
        []
    )

    if isinstance(
        raw_data,
        dict,
    ):
        raw_data = [
            raw_data
        ]

    if not isinstance(
        raw_data,
        list,
    ):
        return []

    results = []

    for item in raw_data:
        parsed = parse_lei_resource(
            item
        )

        if parsed:
            results.append(
                parsed
            )

    return results
