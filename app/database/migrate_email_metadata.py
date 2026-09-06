import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATABASE_PATH = PROJECT_ROOT / "phishing_detector.db"


COLUMNS = {
    "source": "TEXT NOT NULL DEFAULT 'manual'",
    "gmail_message_id": "TEXT",
    "email_subject": "TEXT",
    "email_sender": "TEXT",
}


def get_existing_columns(
    connection: sqlite3.Connection,
) -> set[str]:
    rows = connection.execute(
        "PRAGMA table_info(scan_results)"
    ).fetchall()

    return {row[1] for row in rows}


def main() -> None:
    if not DATABASE_PATH.exists():
        print(f"Database not found: {DATABASE_PATH}")
        return

    with sqlite3.connect(DATABASE_PATH) as connection:
        existing_columns = get_existing_columns(connection)

        for column_name, column_type in COLUMNS.items():
            if column_name in existing_columns:
                print(f"Column already exists: {column_name}")
                continue

            connection.execute(
                f"""
                ALTER TABLE scan_results
                ADD COLUMN {column_name} {column_type}
                """
            )

            print(f"Added column: {column_name}")

        connection.commit()

    print("Database migration completed successfully.")


if __name__ == "__main__":
    main()
