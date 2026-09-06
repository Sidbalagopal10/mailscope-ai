from __future__ import annotations

import sqlite3
from contextvars import ContextVar
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_DATABASE_PATH = Path(
    "data/global_entity_registry/global_entities.db"
)


_DATABASE_OVERRIDE: ContextVar[
    Path | None
] = ContextVar(
    "global_entity_registry_database_override",
    default=None,
)


def active_database_path() -> Path:
    override = _DATABASE_OVERRIDE.get()

    if override is not None:
        return Path(
            override
        )

    return DEFAULT_DATABASE_PATH


@contextmanager
def using_database(
    path: Path | str,
):
    """
    Temporarily redirect ALL registry connection() calls
    in the current execution context to another database.

    Example:

        with using_database(
            Path("data/rehearsal/test.db")
        ):
            import_ror(limit=5000)

    Outside the context, the production registry remains
    the default database.
    """

    resolved = Path(
        path
    )

    token = _DATABASE_OVERRIDE.set(
        resolved
    )

    try:
        yield resolved

    finally:
        _DATABASE_OVERRIDE.reset(
            token
        )


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    canonical_name TEXT NOT NULL,
    entity_type TEXT,
    country_code TEXT,
    country_name TEXT,
    continent TEXT,

    status TEXT NOT NULL DEFAULT 'active',

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    UNIQUE (
        canonical_name,
        country_code
    )
);

CREATE TABLE IF NOT EXISTS entity_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,

    alias TEXT NOT NULL,
    language_code TEXT,

    source_name TEXT NOT NULL,

    FOREIGN KEY (entity_id)
        REFERENCES entities(id)
        ON DELETE CASCADE,

    UNIQUE (
        entity_id,
        alias,
        source_name
    )
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,

    domain TEXT NOT NULL,
    registrable_domain TEXT NOT NULL,

    relationship_type TEXT NOT NULL
        DEFAULT 'official',

    verification_state TEXT NOT NULL
        DEFAULT 'source_verified',

    confidence REAL NOT NULL
        DEFAULT 0.50,

    first_seen_at TEXT NOT NULL,
    last_verified_at TEXT NOT NULL,

    active INTEGER NOT NULL DEFAULT 1,

    FOREIGN KEY (entity_id)
        REFERENCES entities(id)
        ON DELETE CASCADE,

    UNIQUE (
        entity_id,
        domain
    )
);

CREATE TABLE IF NOT EXISTS external_identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,

    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,

    source_name TEXT NOT NULL,

    FOREIGN KEY (entity_id)
        REFERENCES entities(id)
        ON DELETE CASCADE,

    UNIQUE (
        identifier_type,
        identifier_value
    )
);

CREATE TABLE IF NOT EXISTS evidence_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    domain_id INTEGER NOT NULL,

    source_name TEXT NOT NULL,
    source_record_id TEXT,

    source_url TEXT,

    evidence_type TEXT NOT NULL,

    confidence REAL NOT NULL
        DEFAULT 0.50,

    authoritative INTEGER NOT NULL
        DEFAULT 0,

    observed_at TEXT NOT NULL,

    raw_reference TEXT,

    FOREIGN KEY (domain_id)
        REFERENCES domains(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    source_name TEXT NOT NULL,

    started_at TEXT NOT NULL,
    completed_at TEXT,

    records_seen INTEGER NOT NULL
        DEFAULT 0,

    entities_created INTEGER NOT NULL
        DEFAULT 0,

    domains_created INTEGER NOT NULL
        DEFAULT 0,

    errors INTEGER NOT NULL
        DEFAULT 0,

    status TEXT NOT NULL
        DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_domains_domain
ON domains(domain);

CREATE INDEX IF NOT EXISTS idx_domains_registrable
ON domains(registrable_domain);

CREATE INDEX IF NOT EXISTS idx_entities_type
ON entities(entity_type);

CREATE INDEX IF NOT EXISTS idx_entities_country
ON entities(country_code);

CREATE INDEX IF NOT EXISTS idx_entities_continent
ON entities(continent);

CREATE INDEX IF NOT EXISTS idx_aliases_alias
ON entity_aliases(alias);
"""


def initialize_database(
    path: Path | None = None,
) -> None:
    if path is None:
        path = active_database_path()

    path = Path(
        path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with sqlite3.connect(
        path
    ) as connection:
        connection.executescript(
            SCHEMA
        )

        connection.commit()


@contextmanager
def connection(
    path: Path | None = None,
) -> Iterator[sqlite3.Connection]:
    if path is None:
        path = active_database_path()

    path = Path(
        path
    )

    initialize_database(
        path
    )

    database = sqlite3.connect(
        path
    )

    database.row_factory = sqlite3.Row

    try:
        yield database

    finally:
        database.close()
