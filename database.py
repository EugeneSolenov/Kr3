import secrets
import sqlite3
from typing import Any

from config import DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    connection = get_db_connection()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER PRIMARY KEY,
                role TEXT NOT NULL DEFAULT 'user',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def _user_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "password": row["password"],
        "role": row["role"] or "user",
    }


def find_user_by_username(username: str) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT users.id, users.username, users.password, user_roles.role
            FROM users
            LEFT JOIN user_roles ON user_roles.user_id = users.id
            """
        ).fetchall()
    finally:
        connection.close()

    for row in rows:
        if secrets.compare_digest(row["username"], username):
            return _user_from_row(row)
    return None


def create_user(username: str, password_hash: str, role: str = "user") -> dict[str, Any]:
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password_hash),
        )
        user_id = cursor.lastrowid
        connection.execute(
            "INSERT INTO user_roles (user_id, role) VALUES (?, ?)",
            (user_id, role),
        )
        connection.commit()
    finally:
        connection.close()

    user = find_user_by_username(username)
    if user is None:
        raise RuntimeError("Created user was not found")
    return user


def _todo_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "completed": bool(row["completed"]),
    }


def create_todo(title: str, description: str) -> dict[str, Any]:
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, 0)",
            (title, description),
        )
        todo_id = cursor.lastrowid
        connection.commit()
        row = connection.execute(
            "SELECT id, title, description, completed FROM todos WHERE id = ?",
            (todo_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        raise RuntimeError("Created todo was not found")
    return _todo_from_row(row)


def list_todos() -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT id, title, description, completed FROM todos ORDER BY id"
        ).fetchall()
    finally:
        connection.close()

    return [_todo_from_row(row) for row in rows]


def get_todo(todo_id: int) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        row = connection.execute(
            "SELECT id, title, description, completed FROM todos WHERE id = ?",
            (todo_id,),
        ).fetchone()
    finally:
        connection.close()

    return _todo_from_row(row) if row else None


def update_todo(
    todo_id: int,
    title: str,
    description: str,
    completed: bool,
) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            """
            UPDATE todos
            SET title = ?, description = ?, completed = ?
            WHERE id = ?
            """,
            (title, description, int(completed), todo_id),
        )
        connection.commit()
        if cursor.rowcount == 0:
            return None
        row = connection.execute(
            "SELECT id, title, description, completed FROM todos WHERE id = ?",
            (todo_id,),
        ).fetchone()
    finally:
        connection.close()

    return _todo_from_row(row) if row else None


def delete_todo(todo_id: int) -> bool:
    connection = get_db_connection()
    try:
        cursor = connection.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()
