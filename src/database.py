import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .encryptor import Encryptor


@dataclass(frozen=True)
class PasswordRecord:
    id: int
    service: str
    username: str
    password: str


class PasswordManager:
    def __init__(self, database_path="passwords.db", key_path="secret.key"):
        self.database_path = Path(database_path)
        self.encryptor = Encryptor(key_path)
        self._create_schema()

    def _connect(self):
        return sqlite3.connect(self.database_path)

    def _create_schema(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def save_password(self, service, username, password):
        encrypted_password = self.encryptor.encrypt(password)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO passwords (service, username, encrypted_password)
                VALUES (?, ?, ?)
                """,
                (service, username, encrypted_password),
            )
        return cursor.lastrowid

    def list_passwords(self, reveal=False):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, service, username, encrypted_password
                FROM passwords
                ORDER BY service, username
                """
            ).fetchall()

        records = []
        for record_id, service, username, encrypted_password in rows:
            password = self.encryptor.decrypt(encrypted_password) if reveal else "********"
            records.append(PasswordRecord(record_id, service, username, password))
        return records
