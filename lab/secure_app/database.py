"""SWYNEX Web Security Review - Secure Lab Database Module.

Authorized Educational Testbed: Hardened reference implementation.
Demonstrates defense-in-depth:
- Salted PBKDF2-HMAC-SHA256 password hashing (600,000 iterations).
- Prepared statements with strict parameter binding (SQLi prevention).
- Strict DTO / field allowlisting (Mass Assignment prevention).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_portal.db")
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> Tuple[str, str]:
    """Generates a CSPRNG 16-byte salt and PBKDF2-HMAC-SHA256 hash."""
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), pwd_hash.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Verifies password using constant-time comparison."""
    salt = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(pwd_hash.hex(), hash_hex)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes tables and seeds hardened records."""
    target_path = db_path or DB_FILE
    if os.path.exists(target_path):
        os.remove(target_path)

    conn = sqlite3.connect(target_path)
    cursor = conn.cursor()

    # Table 1: Users (Secure schema with salted PBKDF2)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            bio TEXT DEFAULT '',
            api_token TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0
        )
    """)

    # Table 2: Documents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            is_confidential INTEGER DEFAULT 0,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)

    # Table 3: Tickets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            author_name TEXT NOT NULL,
            title TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed Accounts with PBKDF2-HMAC-SHA256
    users_data = [
        ("admin", "AdminP@ss2026!", "admin", "security-admin@swynex.local", "Chief Security Officer", "Corporate systems administrator.", "swynex_live_admin_tok_99182a8b", 1),
        ("alice", "AliceDevPassword99", "developer", "alice.dev@swynex.local", "Alice Vance", "Lead Cloud Architect & DevOps Engineer.", "swynex_dev_alice_tok_44312c1d", 1),
        ("bob", "BobUserPass123", "user", "bob.contractor@swynex.local", "Bob Miller", "External contractor & QA analyst.", "swynex_user_bob_tok_11029f4e", 0),
    ]

    for username, plain_pwd, role, email, full_name, bio, token, is_ver in users_data:
        salt_hex, hash_hex = hash_password(plain_pwd)
        cursor.execute(
            """
            INSERT INTO users (username, salt, password_hash, role, email, full_name, bio, api_token, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, salt_hex, hash_hex, role, email, full_name, bio, token, is_ver),
        )

    # Seed Documents
    seed_docs = [
        (1, 1, "corporate_infrastructure_overview.pdf", "Corporate Infrastructure Overview", "Confidential topology and cloud IP subnets for SWYNEX CloudPortal.", 1),
        (2, 1, "executive_q3_financial_audit.txt", "Q3 Financial Audit Ledger", "Executive payroll, billing statements, and internal account numbers.", 1),
        (3, 2, "api_architecture_v2_spec.pdf", "API Architecture v2 Specification", "Internal microservices documentation and gateway routing.", 0),
        (4, 3, "contractor_guidelines.txt", "Contractor Onboarding Guidelines", "Public rules and workspace setup instructions for contractors.", 0),
    ]

    cursor.executemany(
        """
        INSERT INTO documents (id, owner_id, filename, title, description, is_confidential)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        seed_docs,
    )

    # Seed Tickets
    seed_tickets = [
        (1, 2, "Alice Vance", "System Diagnostic Tool Latency", "The network ping utility seems to take 2-3 seconds on corporate subnets."),
        (2, 3, "Bob Miller", "Request for API Token Rotation", "Please rotate my test API tokens before the upcoming compliance review."),
    ]

    cursor.executemany(
        """
        INSERT INTO tickets (id, author_id, author_name, title, comment)
        VALUES (?, ?, ?, ?, ?)
        """,
        seed_tickets,
    )

    conn.commit()
    conn.close()


def authenticate_user_secure(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Hardened authentication with constant-time hash verification."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    user = dict(row)
    if verify_password(password, user["salt"], user["password_hash"]):
        # Do not return sensitive hash/salt
        safe_user = dict(user)
        safe_user.pop("password_hash", None)
        safe_user.pop("salt", None)
        return safe_user
    return None


def get_user_by_id_secure(user_id: int) -> Optional[Dict[str, Any]]:
    """Returns sanitized user record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, email, full_name, bio, is_verified FROM users WHERE id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_profile_secure(user_id: int, fields: Dict[str, Any]) -> Tuple[bool, str]:
    """DEFENSE: Mitigates Mass Assignment.

    Uses an explicit whitelist of safe user-updatable fields.
    Rejects or ignores unauthorized keys such as 'role', 'is_verified', 'api_token', 'password_hash'.
    """
    ALLOWED_FIELDS = {"full_name", "bio"}
    filtered_updates = {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}

    if not filtered_updates:
        return False, "No permitted fields provided for update"

    conn = get_db_connection()
    cursor = conn.cursor()

    set_clauses = [f"{col} = ?" for col in filtered_updates.keys()]
    values = list(filtered_updates.values())
    values.append(user_id)

    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
    try:
        cursor.execute(query, values)
        conn.commit()
        success = cursor.rowcount > 0
        message = "Profile updated successfully" if success else "User not found"
    except Exception as e:
        success = False
        message = "Database error"
    finally:
        conn.close()

    return success, message


def get_all_documents_secure() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, owner_id, filename, title, description, is_confidential FROM documents ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_document_by_id_secure(doc_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, owner_id, filename, title, description, is_confidential FROM documents WHERE id = ?", (doc_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_tickets_secure() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, author_id, author_name, title, comment, created_at FROM tickets ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_ticket_secure(author_id: int, author_name: str, title: str, comment: str) -> int:
    """Inserts a ticket into database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tickets (author_id, author_name, title, comment) VALUES (?, ?, ?, ?)",
        (author_id, author_name, title, comment),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id or 0


if __name__ == "__main__":
    init_db()
    print(f"[*] Initialized secure portal database at: {DB_FILE}")
