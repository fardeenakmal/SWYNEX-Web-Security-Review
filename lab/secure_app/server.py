"""SWYNEX Web Security Review - Secure Hardened Lab Server.

Port: 8443 (default)
Architecture: Standard library HTTP server implementing defense-in-depth security controls.
Demonstrates production-grade remediations for OWASP Top 10 vulnerabilities.
"""

from __future__ import annotations

import html
import io
import json
import logging
import os
import secrets
import sys
import urllib.parse
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

from .database import (
    add_ticket_secure,
    authenticate_user_secure,
    get_all_documents_secure,
    get_all_tickets_secure,
    get_document_by_id_secure,
    get_user_by_id_secure,
    init_db,
    update_user_profile_secure,
)
from .security_controls import (
    SecurityException,
    create_secure_jwt,
    get_defense_in_depth_headers,
    resolve_safe_file_path,
    safe_fetch_url,
    safe_network_ping,
    sanitize_html_content,
    validate_and_save_upload,
    verify_secure_jwt,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "documents")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
# Cryptographically strong secret key generated or loaded from environment
SECURE_JWT_SECRET = os.environ.get("SWYNEX_JWT_SECRET", secrets.token_hex(32))

ALLOWED_ORIGINS = {
    "http://127.0.0.1:8443",
    "http://localhost:8443",
    "https://cloudportal.swynex.local",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SecurePortal")


class SecurePortalHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler with comprehensive defense-in-depth."""

    server_version = "SWYNEX-SecurePortal/2.0.0"

    def _apply_security_headers(
        self, content_type: str = "text/html; charset=utf-8", status_code: int = 200
    ) -> None:
        """DEFENSE: Applies OWASP-recommended HTTP security headers."""
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)

        # Baseline security headers
        headers = get_defense_in_depth_headers()
        for k, v in headers.items():
            self.send_header(k, v)

        # DEFENSE: Restricted CORS Policy
        req_origin = self.headers.get("Origin")
        if req_origin and req_origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", req_origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
            self.send_header("Vary", "Origin")

        self.end_headers()

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight securely."""
        self._apply_security_headers(status_code=204)

    def _parse_cookies(self) -> Dict[str, str]:
        cookies = {}
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            for item in cookie_header.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    cookies[k] = v
        return cookies

    def _get_authenticated_user(self) -> Optional[Dict[str, Any]]:
        """DEFENSE: Authenticates caller via cryptographically verified HS256 JWT."""
        token = None
        auth_header = self.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            cookies = self._parse_cookies()
            token = cookies.get("session_token")

        if not token:
            return None

        payload = verify_secure_jwt(token, SECURE_JWT_SECRET)
        if payload and "user_id" in payload:
            return get_user_by_id_secure(payload["user_id"])
        return None

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if 0 < content_length <= 1048576:  # 1MB limit
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                return json.loads(body)
            except Exception:
                return {}
        return {}

    def _read_form_body(self) -> Dict[str, str]:
        content_length = int(self.headers.get("Content-Length", 0))
        if 0 < content_length <= 1048576:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(body)
            return {k: v[0] for k, v in parsed.items()}
        return {}

    def do_GET(self) -> None:
        """Route GET requests safely."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        try:
            if path in ("/", "/index.html"):
                self._handle_home()
            elif path == "/login":
                self._handle_login_page()
            elif path == "/dashboard":
                self._handle_dashboard()
            elif path == "/search":
                # DEFENSE: Sanitized Search (Reflected XSS mitigated)
                self._handle_safe_search(query)
            elif path == "/tickets":
                # DEFENSE: Sanitized Tickets (Stored XSS mitigated)
                self._handle_safe_tickets_view()
            elif path == "/api/user/profile":
                # DEFENSE: Enforced BOLA/IDOR Authorization
                self._handle_safe_get_profile(query)
            elif path == "/api/documents":
                self._handle_safe_list_documents()
            elif path == "/api/documents/download":
                # DEFENSE: Path Canonicalization
                self._handle_safe_download(query)
            elif path.startswith("/static/"):
                self._handle_static_files(path)
            else:
                self._apply_security_headers(status_code=404)
                self.wfile.write(b"<h1>404 - Resource Not Found</h1>")
        except SecurityException as se:
            self._handle_security_violation(str(se))
        except Exception as e:
            self._handle_generic_error(e)

    def do_POST(self) -> None:
        """Route POST requests safely."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            if path == "/login":
                self._handle_login_post()
            elif path == "/logout":
                self._handle_logout()
            elif path == "/tickets":
                self._handle_safe_tickets_post()
            elif path == "/api/tools/ping":
                # DEFENSE: Parameterized execution
                data = self._read_json_body() or self._read_form_body()
                target = data.get("target", "127.0.0.1")
                self._handle_safe_ping(target)
            elif path == "/api/tools/fetch-url":
                # DEFENSE: SSRF Filtering
                data = self._read_json_body() or self._read_form_body()
                url = data.get("url", "")
                self._handle_safe_ssrf(url)
            elif path == "/api/upload":
                # DEFENSE: Hardened File Upload
                self._handle_safe_upload()
            else:
                self._apply_security_headers(status_code=404)
                self.wfile.write(b"<h1>404 - Not Found</h1>")
        except SecurityException as se:
            self._handle_security_violation(str(se))
        except Exception as e:
            self._handle_generic_error(e)

    def do_PUT(self) -> None:
        """Route PUT requests safely."""
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/api/user/profile":
            try:
                # DEFENSE: Mass Assignment mitigated via whitelist
                self._handle_safe_update_profile()
            except SecurityException as se:
                self._handle_security_violation(str(se))
            except Exception as e:
                self._handle_generic_error(e)
        else:
            self._apply_security_headers(status_code=404)
            self.wfile.write(b"<h1>404 - Not Found</h1>")

    # =========================================================================
    # HARDENED DEFENSIVE HANDLERS
    # =========================================================================

    def _handle_home(self) -> None:
        user = self._get_authenticated_user()
        user_snippet = (
            f"Logged in as: <strong>{sanitize_html_content(user['username'])}</strong> ({sanitize_html_content(user['role'])}) | <a href='/dashboard'>Dashboard</a> | <a href='/logout'>Logout</a>"
            if user
            else "<a href='/login'>Login to SWYNEX Portal</a>"
        )
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SWYNEX CloudPortal (Hardened Reference)</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .badge {{ background: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #10b981; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ SWYNEX CloudPortal <span class="badge">Hardened Secure Edition</span></h1>
        <p>Production Reference Environment Demonstrating Defense-in-Depth Remediations.</p>
        <p>{user_snippet}</p>
    </div>
    <div class="card">
        <h3>Implemented Defensive Controls</h3>
        <ul>
            <li><strong>Command Injection Mitigated:</strong> RFC 1123 regex whitelist, subprocess execution with <code>shell=False</code>.</li>
            <li><strong>SSRF Mitigated:</strong> DNS pre-resolution, private/loopback/cloud metadata IP validation, redirect blocking.</li>
            <li><strong>XSS Mitigated:</strong> Context-aware HTML entity escaping and strict Content-Security-Policy (CSP).</li>
            <li><strong>Path Traversal Mitigated:</strong> Canonical path verification via <code>os.path.realpath</code> and boundary checks.</li>
            <li><strong>Insecure Upload Mitigated:</strong> Extension allowlisting, magic byte header validation, UUID naming, isolated storage.</li>
            <li><strong>BOLA/IDOR Mitigated:</strong> Strict caller-to-resource ownership checks and RBAC gating.</li>
            <li><strong>Mass Assignment Mitigated:</strong> Explicit DTO allowlisting (rejecting role/token modifications).</li>
            <li><strong>Cryptographic & JWT Hardening:</strong> HS256 algorithm enforcement, expiration checks, PBKDF2-HMAC-SHA256 password hashing.</li>
            <li><strong>Secure Cookie Flags:</strong> <code>HttpOnly; Secure; SameSite=Strict</code>.</li>
            <li><strong>Information Disclosure Mitigated:</strong> Generic error responses with correlation IDs; internal server logging.</li>
        </ul>
    </div>
</body>
</html>"""
        self._apply_security_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_login_page(self) -> None:
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>SWYNEX Login (Secure)</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
        .box { max-width: 400px; margin: auto; background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #475569; background: #0f172a; color: white; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #10b981; border: none; font-weight: bold; border-radius: 4px; cursor: pointer; color: white; }
    </style>
</head>
<body>
    <div class="box">
        <h2>SWYNEX Secure Sign In</h2>
        <form method="POST" action="/login">
            <label>Username:</label>
            <input type="text" name="username" placeholder="e.g. alice, bob, admin" required>
            <label>Password:</label>
            <input type="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
        <p style="font-size: 12px; color: #94a3b8; margin-top: 16px;">
            Seed Accounts (Salted PBKDF2):<br>
            • <code>admin</code> : <code>AdminP@ss2026!</code><br>
            • <code>alice</code> : <code>AliceDevPassword99</code><br>
            • <code>bob</code> : <code>BobUserPass123</code>
        </p>
    </div>
</body>
</html>"""
        self._apply_security_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_login_post(self) -> None:
        data = self._read_form_body() or self._read_json_body()
        username = data.get("username", "").strip()
        password = data.get("password", "")

        user = authenticate_user_secure(username, password)
        if user:
            # DEFENSE: Cryptographically secure JWT signed with HS256
            token = create_secure_jwt(
                {"user_id": user["id"], "username": user["username"], "role": user["role"]},
                SECURE_JWT_SECRET,
                ttl_seconds=3600,
            )

            self.send_response(302)
            self.send_header("Location", "/dashboard")
            # DEFENSE: Hardened Cookie Flags
            self.send_header(
                "Set-Cookie",
                f"session_token={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
            )
            # Baseline security headers
            headers = get_defense_in_depth_headers()
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
        else:
            self._apply_security_headers(status_code=401)
            self.wfile.write(b"<h1>401 - Invalid Credentials</h1><p><a href='/login'>Try again</a></p>")

    def _handle_logout(self) -> None:
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        )
        self.end_headers()

    def _handle_dashboard(self) -> None:
        user = self._get_authenticated_user()
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        safe_name = sanitize_html_content(user.get("full_name", ""))
        safe_username = sanitize_html_content(user.get("username", ""))
        safe_role = sanitize_html_content(user.get("role", ""))

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - SWYNEX Secure</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        a {{ color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Welcome, {safe_name} (@{safe_username})</h2>
        <p>Role: <strong>{safe_role}</strong> | Verified: <strong>{'Yes' if user.get('is_verified') else 'No'}</strong></p>
        <p><a href='/tickets'>Support Feedback Board</a> | <a href='/search?q=CloudPortal'>Search Utility</a> | <a href='/logout'>Sign Out</a></p>
    </div>
    <div class="card">
        <h3>Available Documents</h3>
        <ul>
            <li><a href="/api/documents/download?file=corporate_infrastructure_overview.pdf">corporate_infrastructure_overview.pdf</a></li>
            <li><a href="/api/documents/download?file=contractor_guidelines.txt">contractor_guidelines.txt</a></li>
            <li><a href="/api/documents/download?file=executive_q3_financial_audit.txt">executive_q3_financial_audit.txt</a></li>
        </ul>
    </div>
</body>
</html>"""
        self._apply_security_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_safe_search(self, query: Dict[str, list[str]]) -> None:
        """DEFENSE: Context-aware HTML entity encoding prevents Reflected XSS."""
        raw_q = query.get("q", [""])[0]
        safe_q = sanitize_html_content(raw_q)

        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body style="font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc;">
    <h2>Search Catalog (Hardened)</h2>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{safe_q}" style="padding: 8px; width: 300px;">
        <button type="submit">Search</button>
    </form>
    <hr>
    <div>
        <h3>Search results for: {safe_q}</h3>
        <p>No index items matched your search query.</p>
    </div>
</body>
</html>"""
        self._apply_security_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_safe_tickets_view(self) -> None:
        """DEFENSE: Stored XSS mitigated via HTML entity escaping."""
        tickets = get_all_tickets_secure()
        rows_html = ""
        for t in tickets:
            safe_title = sanitize_html_content(t["title"])
            safe_comment = sanitize_html_content(t["comment"])
            safe_author = sanitize_html_content(t["author_name"])

            rows_html += f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 6px; margin-bottom: 12px; border: 1px solid #334155;">
                <h4>{safe_title}</h4>
                <p>{safe_comment}</p>
                <small style="color: #94a3b8;">Author: {safe_author} | ID: {t['id']}</small>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Support Feedback Board (Hardened)</title></head>
<body style="font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc;">
    <h2>Support & Feedback Board</h2>
    <div style="margin-bottom: 30px; background: #1e293b; padding: 16px; border-radius: 8px;">
        <h3>Submit Feedback</h3>
        <form method="POST" action="/tickets">
            <input type="text" name="title" placeholder="Subject" style="width: 100%; padding: 8px; margin-bottom: 8px;" required><br>
            <textarea name="comment" placeholder="Feedback / Comment" style="width: 100%; height: 80px; padding: 8px;" required></textarea><br>
            <button type="submit" style="padding: 8px 16px; background: #10b981; border: none; font-weight: bold; border-radius: 4px; color: white;">Submit</button>
        </form>
    </div>
    <h3>Recent Tickets:</h3>
    {rows_html}
</body>
</html>"""
        self._apply_security_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_safe_tickets_post(self) -> None:
        user = self._get_authenticated_user()
        author_id = user["id"] if user else 3
        author_name = user["full_name"] if user else "Anonymous Contractor"

        data = self._read_form_body() or self._read_json_body()
        title = data.get("title", "Untitled Feedback").strip()
        comment = data.get("comment", "").strip()

        if not title or not comment:
            raise SecurityException("Title and comment cannot be empty.")

        add_ticket_secure(author_id, author_name, title, comment)
        self.send_response(302)
        self.send_header("Location", "/tickets")
        self.end_headers()

    def _handle_safe_get_profile(self, query: Dict[str, list[str]]) -> None:
        """DEFENSE: BOLA / IDOR Mitigation.

        Enforces caller identity:
        - Callers can ONLY access their own profile (caller_id == requested_id).
        - Administrative users with role == 'admin' can access any profile.
        """
        caller = self._get_authenticated_user()
        if not caller:
            self._apply_security_headers("application/json", status_code=401)
            self.wfile.write(json.dumps({"error": "Authentication required"}).encode("utf-8"))
            return

        user_id_param = query.get("user_id")
        if not user_id_param:
            self._apply_security_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Missing user_id parameter"}).encode("utf-8"))
            return

        try:
            target_id = int(user_id_param[0])
        except ValueError:
            self._apply_security_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Invalid user_id"}).encode("utf-8"))
            return

        # Access Control Check: caller ownership or admin role
        if caller["id"] != target_id and caller["role"] != "admin":
            logger.warning(
                f"BOLA/IDOR attempt blocked: User {caller['id']} tried to access User {target_id} profile."
            )
            self._apply_security_headers("application/json", status_code=403)
            self.wfile.write(
                json.dumps(
                    {
                        "error": "Forbidden: Horizontal privilege boundary violation.",
                        "details": "You are not authorized to view this user profile.",
                    }
                ).encode("utf-8")
            )
            return

        target_user = get_user_by_id_secure(target_id)
        if not target_user:
            self._apply_security_headers("application/json", status_code=404)
            self.wfile.write(json.dumps({"error": "User not found"}).encode("utf-8"))
            return

        self._apply_security_headers("application/json")
        self.wfile.write(json.dumps(target_user).encode("utf-8"))

    def _handle_safe_update_profile(self) -> None:
        """DEFENSE: Mass Assignment Mitigation.

        Strictly allowlists updatable fields ('full_name', 'bio').
        Rejects or ignores unauthorized elevation attempts (e.g. 'role', 'is_verified').
        """
        caller = self._get_authenticated_user()
        if not caller:
            self._apply_security_headers("application/json", status_code=401)
            self.wfile.write(json.dumps({"error": "Authentication required"}).encode("utf-8"))
            return

        payload = self._read_json_body()
        if not payload:
            self._apply_security_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Invalid or empty JSON body"}).encode("utf-8"))
            return

        # Detect privilege escalation attempts
        unauthorized_keys = {"role", "is_verified", "api_token", "password_hash", "salt"}
        attempted_violations = [k for k in payload.keys() if k in unauthorized_keys]
        if attempted_violations:
            logger.warning(
                f"Mass assignment attack detected from User {caller['id']}: attempted fields {attempted_violations}"
            )

        success, message = update_user_profile_secure(caller["id"], payload)
        if success:
            updated = get_user_by_id_secure(caller["id"])
            self._apply_security_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "status": "success",
                        "message": message,
                        "user": updated,
                        "ignored_privileged_fields": attempted_violations,
                    }
                ).encode("utf-8")
            )
        else:
            self._apply_security_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": message}).encode("utf-8"))

    def _handle_safe_list_documents(self) -> None:
        docs = get_all_documents_secure()
        self._apply_security_headers("application/json")
        self.wfile.write(json.dumps({"documents": docs}).encode("utf-8"))

    def _handle_safe_download(self, query: Dict[str, list[str]]) -> None:
        """DEFENSE: Path Traversal Mitigation.

        Enforces strict path canonicalization and verifies destination path
        is strictly contained within DOCS_DIR.
        """
        filename = query.get("file", [""])[0]
        if not filename:
            self._apply_security_headers(status_code=400)
            self.wfile.write(b"<h1>400 - Missing file parameter</h1>")
            return

        # Canonicalizes path and prevents traversal outside DOCS_DIR
        safe_path = resolve_safe_file_path(DOCS_DIR, filename)

        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            self._apply_security_headers(status_code=404)
            self.wfile.write(b"<h1>404 - Document Not Found</h1>")
            return

        with open(safe_path, "rb") as f:
            content = f.read()

        content_type = "text/plain; charset=utf-8"
        if filename.endswith(".pdf"):
            content_type = "application/pdf"

        self._apply_security_headers(content_type)
        self.wfile.write(content)

    def _handle_safe_ping(self, target: str) -> None:
        """DEFENSE: Command Injection Mitigation.

        Validates host format via regex and executes subprocess with shell=False.
        """
        result = safe_network_ping(target)
        self._apply_security_headers("application/json")
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def _handle_safe_ssrf(self, url: str) -> None:
        """DEFENSE: SSRF Mitigation.

        Pre-validates destination IP against RFC 1918, loopback, and cloud metadata.
        Disables automatic redirection.
        """
        if not url:
            self._apply_security_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Missing URL parameter"}).encode("utf-8"))
            return

        result = safe_fetch_url(url)
        self._apply_security_headers("application/json")
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def _handle_safe_upload(self) -> None:
        """DEFENSE: Hardened File Upload.

        Enforces extension whitelist (.png, .jpg), magic byte signature check,
        size limitation, and random UUID naming.
        """
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))

        if "multipart/form-data" in content_type:
            boundary = content_type.split("boundary=")[1].encode("utf-8")
            raw_body = self.rfile.read(content_length)

            client_filename = "upload.bin"
            file_data = b""

            for part in raw_body.split(b"--" + boundary):
                if b"filename=" in part:
                    header_part, body_part = part.split(b"\r\n\r\n", 1)
                    body_part = body_part.rstrip(b"\r\n--")
                    header_str = header_part.decode("utf-8", errors="replace")
                    for line in header_str.split("\r\n"):
                        if "filename=" in line:
                            client_filename = line.split("filename=")[1].strip('"')
                    file_data = body_part
                    break

            stored_name, path = validate_and_save_upload(client_filename, file_data, UPLOADS_DIR)
            self._apply_security_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "status": "success",
                        "assigned_filename": stored_name,
                        "bytes_saved": len(file_data),
                    }
                ).encode("utf-8")
            )
        else:
            client_filename = self.headers.get("X-Filename", "upload.dat")
            file_data = self.rfile.read(content_length)
            stored_name, path = validate_and_save_upload(client_filename, file_data, UPLOADS_DIR)
            self._apply_security_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "status": "success",
                        "assigned_filename": stored_name,
                        "bytes_saved": len(file_data),
                    }
                ).encode("utf-8")
            )

    def _handle_static_files(self, path: str) -> None:
        rel_path = path[len("/static/") :]
        safe_path = resolve_safe_file_path(os.path.join(BASE_DIR, "static"), rel_path)
        if os.path.exists(safe_path) and os.path.isfile(safe_path):
            with open(safe_path, "rb") as f:
                content = f.read()
            self._apply_security_headers("text/css" if path.endswith(".css") else "text/javascript")
            self.wfile.write(content)
        else:
            self._apply_security_headers(status_code=404)
            self.wfile.write(b"404 Static Not Found")

    def _handle_security_violation(self, reason: str) -> None:
        """Handles caught security policy violations safely."""
        logger.warning(f"Security control violation: {reason}")
        self._apply_security_headers("application/json", status_code=400)
        self.wfile.write(
            json.dumps(
                {
                    "error": "Defensive Security Policy Violation",
                    "reason": reason,
                    "code": "SEC_CONTROL_BLOCKED",
                }
            ).encode("utf-8")
        )

    def _handle_generic_error(self, exc: Exception) -> None:
        """DEFENSE: Information Disclosure Mitigation.

        Logs error internally with unique correlation ID and returns a safe generic message.
        """
        request_id = str(uuid.uuid4())
        logger.error(f"Internal error [Request-ID: {request_id}]: {str(exc)}", exc_info=True)

        self._apply_security_headers("application/json", status_code=500)
        self.wfile.write(
            json.dumps(
                {
                    "error": "An internal server error occurred.",
                    "request_id": request_id,
                    "message": "Refer to operational logs for diagnostic traces.",
                }
            ).encode("utf-8")
        )


def run_server(port: int = 8443, host: str = "127.0.0.1") -> None:
    """Initializes DB and runs secure hardened server."""
    init_db()
    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    server_address = (host, port)
    httpd = HTTPServer(server_address, SecurePortalHandler)
    print(f"[*] SWYNEX Secure Hardened Portal running at http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down secure server.")
        httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    run_server(port=port_arg)
