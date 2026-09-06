from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Iterator

from lxml import etree


def local_name(
    element: etree._Element,
) -> str:
    return etree.QName(
        element.tag
    ).localname


def first_text(
    element: etree._Element,
    name: str,
) -> str | None:
    for child in element.iter():
        if local_name(
            child
        ) != name:
            continue

        if child.text:
            cleaned = child.text.strip()

            if cleaned:
                return cleaned

    return None


def first_child(
    element: etree._Element,
    name: str,
) -> etree._Element | None:
    for child in element.iter():
        if local_name(
            child
        ) == name:
            return child

    return None


def address(
    entity: etree._Element,
    field_name: str,
) -> dict[str, Any]:
    node = first_child(
        entity,
        field_name,
    )

    if node is None:
        return {
            "country": None,
            "region": None,
            "city": None,
        }

    return {
        "country": first_text(
            node,
            "Country",
        ),
        "region": first_text(
            node,
            "Region",
        ),
        "city": first_text(
            node,
            "City",
        ),
    }


def parse_lei_record(
    element: etree._Element,
) -> dict[str, Any] | None:
    lei = first_text(
        element,
        "LEI",
    )

    entity = first_child(
        element,
        "Entity",
    )

    registration = first_child(
        element,
        "Registration",
    )

    if (
        not lei
        or entity is None
        or registration is None
    ):
        return None

    legal_name_node = first_child(
        entity,
        "LegalName",
    )

    legal_name = (
        legal_name_node.text.strip()
        if (
            legal_name_node is not None
            and legal_name_node.text
        )
        else None
    )

    if not legal_name:
        return None

    legal_address = address(
        entity,
        "LegalAddress",
    )

    headquarters = address(
        entity,
        "HeadquartersAddress",
    )

    other_names = []

    other_names_node = first_child(
        entity,
        "OtherEntityNames",
    )

    if other_names_node is not None:
        for child in other_names_node.iter():
            if local_name(
                child
            ) != "OtherEntityName":
                continue

            if not child.text:
                continue

            value = child.text.strip()

            if not value:
                continue

            other_names.append(
                {
                    "name": value,
                    "type": child.attrib.get(
                        "type",
                        "other",
                    ),
                    "language": child.attrib.get(
                        "{http://www.w3.org/XML/1998/namespace}lang"
                    ),
                }
            )

    return {
        "lei": lei,
        "legal_name": legal_name,
        "legal_name_language": (
            legal_name_node.attrib.get(
                "{http://www.w3.org/XML/1998/namespace}lang"
            )
            if legal_name_node is not None
            else None
        ),
        "entity_status": first_text(
            entity,
            "EntityStatus",
        ),
        "jurisdiction": first_text(
            entity,
            "LegalJurisdiction",
        ),
        "legal_form_code": first_text(
            entity,
            "EntityLegalFormCode",
        ),
        "registration_authority_id": first_text(
            entity,
            "RegistrationAuthorityID",
        ),
        "registration_authority_entity_id": first_text(
            entity,
            "RegistrationAuthorityEntityID",
        ),
        "headquarters_country": headquarters[
            "country"
        ],
        "headquarters_region": headquarters[
            "region"
        ],
        "headquarters_city": headquarters[
            "city"
        ],
        "legal_address_country": legal_address[
            "country"
        ],
        "legal_address_region": legal_address[
            "region"
        ],
        "legal_address_city": legal_address[
            "city"
        ],
        "initial_registration_date": first_text(
            registration,
            "InitialRegistrationDate",
        ),
        "last_update_date": first_text(
            registration,
            "LastUpdateDate",
        ),
        "next_renewal_date": first_text(
            registration,
            "NextRenewalDate",
        ),
        "managing_lou": first_text(
            registration,
            "ManagingLOU",
        ),
        "other_names": other_names,
    }


def xml_member(
    zip_path: Path,
) -> str:
    with zipfile.ZipFile(
        zip_path
    ) as archive:
        members = [
            name
            for name in archive.namelist()
            if name.lower().endswith(
                ".xml"
            )
        ]

    if not members:
        raise ValueError(
            "GLEIF ZIP contained no XML file."
        )

    return members[0]


def iter_lei_records(
    zip_path: Path,
) -> Iterator[dict[str, Any]]:
    member = xml_member(
        zip_path
    )

    with zipfile.ZipFile(
        zip_path
    ) as archive:
        with archive.open(
            member
        ) as stream:
            context = etree.iterparse(
                stream,
                events=(
                    "end",
                ),
            )

            for _event, element in context:
                if local_name(
                    element
                ) != "LEIRecord":
                    continue

                record = parse_lei_record(
                    element
                )

                if record:
                    yield record

                element.clear()

                parent = element.getparent()

                while (
                    parent is not None
                    and element.getprevious()
                    is not None
                ):
                    del parent[0]
