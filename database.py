"""
database.py
===========
Database layer (the "Database" component in Chapter 3).

Uses SQLite so there is nothing to install or configure. Stores:
  - users            : usernames + hashed passwords (never plain text)
  - auth_sessions    : pending login attempts and whether the QR has been
                       scanned/verified yet (the second factor state)
  - logs             : an audit trail of authentication events

A hashed password and a token fingerprint are the only credential-related
values ever written to disk, which is the behaviour recommended in the
Literature Review.
"""

import sqlite3
import time
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "2fa_system.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables (if missing) and seed one demo user."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_id  TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            token_hash  TEXT NOT NULL,
            expires_at  INTEGER NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            used        INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            event      TEXT NOT NULL,
            detail     TEXT,
            created_at INTEGER NOT NULL
        )
    """)

    # Seed a demo account if the table is empty.
    cur.execute("SELECT COUNT(*) AS n FROM users")
    if cur.fetchone()["n"] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("student", generate_password_hash("password123")),
        )

    conn.commit()
    conn.close()


# ----------------------------- Users ---------------------------------- #
def verify_user(username: str, password: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row is None:
        return False
    return check_password_hash(row["password_hash"], password)


def create_user(username: str, password: str) -> bool:
    """Register a new user. Returns False if the username already exists."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# ------------------------- Auth sessions ------------------------------ #
def create_auth_session(session_id, username, token_hash, expires_at):
    conn = get_connection()
    conn.execute(
        """INSERT INTO auth_sessions
           (session_id, username, token_hash, expires_at, verified, used, created_at)
           VALUES (?, ?, ?, ?, 0, 0, ?)""",
        (session_id, username, token_hash, expires_at, int(time.time())),
    )
    conn.commit()
    conn.close()


def get_auth_session(session_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM auth_sessions WHERE session_id = ?", (session_id,)
    ).fetchone()
    conn.close()
    return row


def mark_session_verified(session_id):
    conn = get_connection()
    conn.execute(
        "UPDATE auth_sessions SET verified = 1, used = 1 WHERE session_id = ?",
        (session_id,),
    )
    conn.commit()
    conn.close()


# ------------------------------ Logs ---------------------------------- #
def add_log(username, event, detail=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO logs (username, event, detail, created_at) VALUES (?, ?, ?, ?)",
        (username, event, detail, int(time.time())),
    )
    conn.commit()
    conn.close()


def get_recent_logs(limit=20):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return rows
