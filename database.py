import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from passlib.context import CryptContext

load_dotenv()

DB_PATH = Path("data/app.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _build_cipher() -> Fernet:
    key = os.getenv("TOKEN_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("TOKEN_ENCRYPTION_KEY must be set to a Fernet key.")
    try:
        return Fernet(key.encode())
    except Exception as exc:
        raise RuntimeError("TOKEN_ENCRYPTION_KEY must be a valid base64-encoded Fernet key.") from exc


CIPHER = _build_cipher()


@dataclass
class User:
    id: int
    email: str
    role: str
    hashed_password: str


@dataclass
class Client:
    id: int
    name: str
    client_key: str
    owner_user_id: int
    connected: bool
    realm_id: Optional[str]


@dataclass
class TokenRecord:
    client_key: str
    realm_id: str
    access_token: str
    refresh_token: str
    expires_at: int


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> bool:
    first_time = not DB_PATH.exists()
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                client_key TEXT,
                action TEXT NOT NULL,
                metadata TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                client_key TEXT NOT NULL UNIQUE,
                owner_user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(owner_user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                client_key TEXT PRIMARY KEY,
                realm_id TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(client_key) REFERENCES clients(client_key)
            )
            """
        )
    _ensure_default_admin()
    return first_time


def _ensure_default_admin() -> None:
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    if not email or not password:
        return
    if get_user_by_email(email):
        return
    try:
        create_user(email=email, password=password, role="admin")
    except ValueError as exc:
        raise RuntimeError(f"Failed to create default admin: {exc}") from exc


def create_user(email: str, password: str, role: str) -> User:
    secret = _normalize_password(password)
    hashed = pwd_context.hash(secret)
    now = int(time.time())
    with _get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (email, hashed_password, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (email.lower().strip(), hashed, role, now),
        )
        user_id = cur.lastrowid
    return User(id=user_id, email=email.lower().strip(), role=role, hashed_password=hashed)


def get_user_by_email(email: str) -> Optional[User]:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT id, email, hashed_password, role FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
    return _row_to_user(row)


def get_user_by_id(user_id: int) -> Optional[User]:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT id, email, hashed_password, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return _row_to_user(row)


def verify_user_credentials(email: str, password: str) -> Optional[User]:
    user = get_user_by_email(email)
    if not user:
        return None
    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user


def create_client_account(name: str, email: str, password: str) -> Client:
    if get_user_by_email(email):
        raise ValueError("A user with that email already exists.")
    client_user = create_user(email=email, password=password, role="client")
    client_key = secrets.token_urlsafe(12)
    now = int(time.time())
    with _get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO clients (name, client_key, owner_user_id, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name.strip(), client_key, client_user.id, now),
        )
        client_id = cur.lastrowid
    return Client(
        id=client_id,
        name=name.strip(),
        client_key=client_key,
        owner_user_id=client_user.id,
        connected=False,
        realm_id=None,
    )


def list_clients_for_user(user: User) -> List[Client]:
    query = """
        SELECT c.id, c.name, c.client_key, c.owner_user_id, t.realm_id,
               CASE WHEN t.client_key IS NULL THEN 0 ELSE 1 END AS connected
        FROM clients c
        LEFT JOIN tokens t ON t.client_key = c.client_key
    """
    params: tuple = ()
    if user.role != "admin":
        query += " WHERE c.owner_user_id = ?"
        params = (user.id,)
    query += " ORDER BY c.created_at DESC"

    with _get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        Client(
            id=row["id"],
            name=row["name"],
            client_key=row["client_key"],
            owner_user_id=row["owner_user_id"],
            connected=bool(row["connected"]),
            realm_id=row["realm_id"],
        )
        for row in rows
    ]


def ensure_client_access(client_key: str, user: User) -> Client:
    with _get_connection() as conn:
        row = conn.execute(
            """
            SELECT c.id, c.name, c.client_key, c.owner_user_id, t.realm_id,
                   CASE WHEN t.client_key IS NULL THEN 0 ELSE 1 END AS connected
            FROM clients c
            LEFT JOIN tokens t ON t.client_key = c.client_key
            WHERE c.client_key = ?
            """,
            (client_key,),
        ).fetchone()

    client = None
    if row:
        client = Client(
            id=row["id"],
            name=row["name"],
            client_key=row["client_key"],
            owner_user_id=row["owner_user_id"],
            connected=bool(row["connected"]),
            realm_id=row["realm_id"],
        )

    if client is None:
        raise ValueError("Client not found.")
    if user.role != "admin" and client.owner_user_id != user.id:
        raise PermissionError("You do not have access to this client.")
    return client


def delete_client_account(client_key: str) -> bool:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT owner_user_id FROM clients WHERE client_key = ?",
            (client_key,),
        ).fetchone()
        if not row:
            return False
        owner_id = row["owner_user_id"]
        conn.execute("DELETE FROM tokens WHERE client_key = ?", (client_key,))
        conn.execute("DELETE FROM clients WHERE client_key = ?", (client_key,))
        conn.execute("DELETE FROM users WHERE id = ?", (owner_id,))
    return True


def update_user_credentials(user_id: int, *, email: Optional[str] = None, password: Optional[str] = None) -> User:
    email_value = None
    if email:
        email_value = email.strip().lower()
        if not email_value:
            raise ValueError("Email cannot be empty.")
        with _get_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email_value,)).fetchone()
            if existing and existing["id"] != user_id:
                raise ValueError("Email already in use.")
    password_hash = None
    if password:
        password_hash = pwd_context.hash(_normalize_password(password))

    if not email_value and not password_hash:
        raise ValueError("No changes requested.")

    updates = []
    params = []
    if email_value:
        updates.append("email = ?")
        params.append(email_value)
    if password_hash:
        updates.append("hashed_password = ?")
        params.append(password_hash)
    params.append(user_id)

    with _get_connection() as conn:
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

    updated = get_user_by_id(user_id)
    if not updated:
        raise ValueError("User not found after update.")
    return updated


def save_tokens(record: TokenRecord) -> None:
    now = int(time.time())
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO tokens (client_key, realm_id, access_token, refresh_token, expires_at, updated_at)
            VALUES (:client_key, :realm_id, :access_token, :refresh_token, :expires_at, :updated_at)
            ON CONFLICT(client_key) DO UPDATE SET
                realm_id=excluded.realm_id,
                access_token=excluded.access_token,
                refresh_token=excluded.refresh_token,
                expires_at=excluded.expires_at,
                updated_at=excluded.updated_at
            """,
            {
                "client_key": record.client_key,
                "realm_id": record.realm_id,
                "access_token": _encrypt(record.access_token),
                "refresh_token": _encrypt(record.refresh_token),
                "expires_at": record.expires_at,
                "updated_at": now,
            },
        )


def get_tokens(client_key: str) -> Optional[TokenRecord]:
    with _get_connection() as conn:
        row = conn.execute(
            """
            SELECT client_key, realm_id, access_token, refresh_token, expires_at
            FROM tokens
            WHERE client_key = ?
            """,
            (client_key,),
        ).fetchone()

    if row is None:
        return None

    return TokenRecord(
        client_key=row["client_key"],
        realm_id=row["realm_id"],
        access_token=_decrypt(row["access_token"]),
        refresh_token=_decrypt(row["refresh_token"]),
        expires_at=row["expires_at"],
    )


def delete_tokens(client_key: str) -> None:
    with _get_connection() as conn:
        conn.execute("DELETE FROM tokens WHERE client_key = ?", (client_key,))


def record_audit_event(user_id: Optional[int], client_key: Optional[str], action: str, metadata: Optional[str] = None) -> None:
    now = int(time.time())
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (user_id, client_key, action, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, client_key, action, metadata, now),
        )


def list_all_clients() -> List[Client]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT c.id, c.name, c.client_key, c.owner_user_id, t.realm_id,
                   CASE WHEN t.client_key IS NULL THEN 0 ELSE 1 END AS connected
            FROM clients c
            LEFT JOIN tokens t ON t.client_key = c.client_key
            ORDER BY c.created_at DESC
            """
        ).fetchall()

    return [
        Client(
            id=row["id"],
            name=row["name"],
            client_key=row["client_key"],
            owner_user_id=row["owner_user_id"],
            connected=bool(row["connected"]),
            realm_id=row["realm_id"],
        )
        for row in rows
    ]


def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[User]:
    if row is None:
        return None
    return User(
        id=row["id"],
        email=row["email"],
        role=row["role"],
        hashed_password=row["hashed_password"],
    )


def _encrypt(value: str) -> str:
    return CIPHER.encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    return CIPHER.decrypt(value.encode()).decode()


def _normalize_password(password: str) -> str:
    if password is None:
        raise ValueError("Password is required.")
    secret = password.strip()
    if not secret:
        raise ValueError("Password cannot be empty.")
    if len(secret.encode("utf-8")) > 72:
        raise ValueError("Password too long. Use 72 characters or fewer.")
    return secret


DB_INITIALIZED_NEW = init_db()
