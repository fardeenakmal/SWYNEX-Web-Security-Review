"""SWYNEX Web Security Review - Vulnerable Lab Database Module.

Authorized Educational Testbed: Demonstrates common web security flaws.
Database: SQLite with intentionally insecure query execution & schema design.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from typing import Any, Dict, List, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_portal.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dictionary-like row factory."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes tables and seeds initial testbed data."""
    target_path = db_path or DB_FILE
    if os.path.exists(target_path):
        os.remove(target_path)

    conn = sqlite3.connect(target_path)
    cursor = conn.cursor()

    # Table 1: Users (Insecure storage: MD5 password, role flag susceptible to mass assignment)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            bio TEXT DEFAULT '',
            api_token TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0
        )
    """)

    # Table 2: Enterprise Documents (Susceptible to IDOR and Path Traversal)
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

    # Table 3: Tickets / Feedback (Susceptible to Stored XSS)
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

    # Seed Users
    # Note: Weak MD5 hashing without salt (demonstrates cryptographic weakness)
    seed_users = [
        (
            1,
            "admin",
            hashlib.md5(b"AdminP@ss2026!").hexdigest(),
            "admin",
            "security-admin@swynex.local",
            "Chief Security Officer",
            "Corporate systems administrator and security oversight.",
            "swynex_live_admin_tok_99182a8b",
            1,
        ),
        (
            2,
            "alice",
            hashlib.md5(b"AliceDevPassword99").hexdigest(),
            "developer",
            "alice.dev@swynex.local",
            "Alice Vance",
            "Lead Cloud Architect & DevOps Engineer.",
            "swynex_dev_alice_tok_44312c1d",
            1,
        ),
        (
            3,
            "bob",
            hashlib.md5(b"BobUserPass123").hexdigest(),
            "user",
            "bob.contractor@swynex.local",
            "Bob Miller",
            "External contractor & QA analyst.",
            "swynex_user_bob_tok_11029f4e",
            0,
        ),
    ]

    cursor.executemany(
        """
        INSERT INTO users (id, username, password, role, email, full_name, bio, api_token, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        seed_users,
    )

    # Seed Documents
    seed_docs = [
        (
            1,
            1,
            "corporate_infrastructure_overview.pdf",
            "Corporate Infrastructure Overview",
            "Confidential topology and cloud IP subnets for SWYNEX CloudPortal.",
            1,
        ),
        (
            2,
            1,
            "executive_q3_financial_audit.txt",
            "Q3 Financial Audit Ledger",
            "Executive payroll, billing statements, and internal account numbers.",
            1,
        ),
        (
            3,
            2,
            "api_architecture_v2_spec.pdf",
            "API Architecture v2 Specification",
            "Internal microservices documentation and gateway routing.",
            0,
        ),
        (
            4,
            3,
            "contractor_guidelines.txt",
            "Contractor Onboarding Guidelines",
            "Public rules and workspace setup instructions for contractors.",
            0,
        ),
    ]

    cursor.executemany(
        """
        INSERT INTO documents (id, owner_id, filename, title, description, is_confidential)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        seed_docs,
    )

    # Seed Support Tickets (Demonstrates stored feedback)
    seed_tickets = [
        (
            1,
            2,
            "Alice Vance",
            "System Diagnostic Tool Latency",
            "The network ping utility seems to take 2-3 seconds on corporate subnets.",
        ),
        (
            2,
            3,
            "Bob Miller",
            "Request for API Token Rotation",
            "Please rotate my test API tokens before the upcoming compliance review.",
        ),
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


def find_user_by_credentials(username: str, password_hash: str) -> Optional[Dict[str, Any]]:
    """Vulnerable authentication query - direct lookup."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password_hash),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Returns user record by integer ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_profile_vulnerable(user_id: int, fields: Dict[str, Any]) -> bool:
    """VULNERABILITY: Mass Assignment flaw.

    Directly applies arbitrary request payload keys into database columns without allowlisting.
    Allows unprivileged users to update 'role', 'is_verified', 'api_token', etc.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    set_clauses = []
    values = []
    for key, value in fields.items():
        # Blindly trusts client-supplied keys and values
        set_clauses.append(f"{key} = ?")
        values.append(value)

    if not set_clauses:
        conn.close()
        return False

    values.append(user_id)
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
    try:
        cursor.execute(query, values)
        conn.commit()
        success = cursor.rowcount > 0
    except Exception:
        success = False
    finally:
        conn.close()
    return success


def get_all_documents() -> List[Dict[str, Any]]:
    """Returns all documents."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_document_by_id(doc_id: int) -> Optional[Dict[str, Any]]:
    """Returns document record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_tickets() -> List[Dict[str, Any]]:
    """Returns all ticket/comment entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tickets ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_ticket(author_id: int, author_name: str, title: str, comment: str) -> int:
    """Inserts a new ticket/comment without HTML sanitization (Stored XSS)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO tickets (author_id, author_name, title, comment)
        VALUES (?, ?, ?, ?)
        """,
        (author_id, author_name, title, comment),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id or 0


if __name__ == "__main__":
    init_db()
    print(f"[*] Initialized vulnerable portal database at: {DB_FILE}")

