import os
import sqlite3


def get_user(db_path: str, username: str):
    """Retrieve a user with a parameterised query."""
    conn = sqlite3.connect(db_path)
    return conn.execute(
        "SELECT id, name FROM users WHERE name = ?", (username,)
    ).fetchall()


def main() -> None:
    print(get_user(os.environ.get("DB_PATH", "app.db"), "alice"))
