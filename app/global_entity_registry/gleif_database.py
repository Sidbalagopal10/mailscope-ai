from __future__ import annotations

from app.global_entity_registry.database import (
    connection,
)


GLEIF_SCHEMA = """
CREATE TABLE IF NOT EXISTS legal_entity_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    entity_id INTEGER,

    lei TEXT NOT NULL UNIQUE,

    legal_name TEXT NOT NULL,
    legal_name_language TEXT,

    entity_status TEXT,

    jurisdiction TEXT,
    legal_form_code TEXT,

    registration_authority_id TEXT,
    registration_authority_entity_id TEXT,

    headquarters_country TEXT,
    headquarters_region TEXT,
    headquarters_city TEXT,

    legal_address_country TEXT,
    legal_address_region TEXT,
    legal_address_city TEXT,

    initial_registration_date TEXT,
    last_update_date TEXT,
    next_renewal_date TEXT,

    managing_lou TEXT,

    source_name TEXT NOT NULL
        DEFAULT 'gleif',

    imported_at TEXT NOT NULL,

    FOREIGN KEY (entity_id)
        REFERENCES entities(id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS legal_entity_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    legal_entity_profile_id INTEGER NOT NULL,

    name TEXT NOT NULL,
    name_type TEXT NOT NULL,

    language_code TEXT,

    FOREIGN KEY (legal_entity_profile_id)
        REFERENCES legal_entity_profiles(id)
        ON DELETE CASCADE,

    UNIQUE (
        legal_entity_profile_id,
        name,
        name_type
    )
);

CREATE TABLE IF NOT EXISTS legal_entity_registration_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    legal_entity_profile_id INTEGER NOT NULL,

    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,

    authority TEXT,

    FOREIGN KEY (legal_entity_profile_id)
        REFERENCES legal_entity_profiles(id)
        ON DELETE CASCADE,

    UNIQUE (
        legal_entity_profile_id,
        identifier_type,
        identifier_value
    )
);

CREATE TABLE IF NOT EXISTS legal_entity_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    parent_lei TEXT,
    child_lei TEXT,

    relationship_type TEXT NOT NULL,

    relationship_status TEXT,

    source_name TEXT NOT NULL
        DEFAULT 'gleif',

    observed_at TEXT NOT NULL,

    UNIQUE (
        parent_lei,
        child_lei,
        relationship_type
    )
);

CREATE TABLE IF NOT EXISTS entity_resolution_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    registry_entity_id INTEGER NOT NULL,
    lei TEXT NOT NULL,

    name_similarity REAL NOT NULL
        DEFAULT 0.0,

    country_agreement INTEGER NOT NULL
        DEFAULT 0,

    external_id_agreement INTEGER NOT NULL
        DEFAULT 0,

    confidence REAL NOT NULL
        DEFAULT 0.0,

    decision TEXT NOT NULL
        DEFAULT 'candidate',

    evidence TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY (registry_entity_id)
        REFERENCES entities(id)
        ON DELETE CASCADE,

    UNIQUE (
        registry_entity_id,
        lei
    )
);

CREATE INDEX IF NOT EXISTS idx_legal_profiles_lei
ON legal_entity_profiles(lei);

CREATE INDEX IF NOT EXISTS idx_legal_profiles_name
ON legal_entity_profiles(legal_name);

CREATE INDEX IF NOT EXISTS idx_legal_profiles_country
ON legal_entity_profiles(legal_address_country);

CREATE INDEX IF NOT EXISTS idx_legal_names_name
ON legal_entity_names(name);

CREATE INDEX IF NOT EXISTS idx_entity_resolution_registry
ON entity_resolution_candidates(registry_entity_id);

CREATE INDEX IF NOT EXISTS idx_entity_resolution_lei
ON entity_resolution_candidates(lei);
"""


def initialize_gleif_schema() -> None:
    with connection() as db:
        db.executescript(
            GLEIF_SCHEMA
        )

        db.commit()


if __name__ == "__main__":
    initialize_gleif_schema()

    print(
        "GLEIF schema initialized."
    )
