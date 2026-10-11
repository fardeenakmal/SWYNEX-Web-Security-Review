"""SWYNEX Web Security Review - Vulnerable Lab Server.

Port: 8000 (default)
Architecture: Standard library HTTP server intentionally implementing common web flaws.
WARNING: STRICTLY FOR EDUCATIONAL DEFENSIVE AUDITING IN AN ISOLATED TESTBED.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import os
import subprocess
import sys
import traceback
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

from .database import (
    add_ticket,
    find_user_by_credentials,
    get_all_documents,
    get_all_tickets,
    get_document_by_id,
    get_user_by_id,
    init_db,
    update_user_profile_vulnerable,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "documents")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
SECRET_KEY = "weak_lab_secret_key_123"  # Insecure hardcoded weak key


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode("utf-8"))


def create_insecure_jwt(payload: Dict[str, Any], alg: str = "HS256") -> str:
    """Creates a JWT token.

    VULNERABILITY: Insecure cryptographic implementation.
    Permits 'none' algorithm and uses weak hardcoded secret.
    """
    header = {"typ": "JWT", "alg": alg}
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    if alg.lower() == "none":
        signature_b64 = ""
    else:
        sig = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature_b64 = base64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_insecure_jwt(token: str) -> Optional[Dict[str, Any]]:
    """VULNERABILITY: Broken JWT verification.

    1. Accepts algorithm 'none' without signature verification.
    2. Does not enforce expiration timestamps.
    """
    try:
        parts = token.split(".")
        if len(parts) not in (2, 3):
            return None

        header_json = json.loads(base64url_decode(parts[0]).decode("utf-8"))
        payload_json = json.loads(base64url_decode(parts[1]).decode("utf-8"))
        alg = header_json.get("alg", "").lower()

        if alg == "none":
            # Insecurely accepts unsigned token!
            return payload_json

        if len(parts) == 3:
            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
            expected_sig = base64url_encode(
                hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
            )
            if parts[2] == expected_sig:
                return payload_json
    except Exception:
        return None
    return None


class VulnerablePortalHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler intentionally exhibiting OWASP Top 10 vulnerabilities."""

    server_version = "SWYNEX-VulnerablePortal/1.0.0"

    def _set_vulnerable_headers(
        self, content_type: str = "text/html; charset=utf-8", status_code: int = 200
    ) -> None:
        """VULNERABILITY: Security Misconfiguration & Insecure CORS.

        - Wildcard Access-Control-Allow-Origin with credentials
        - Omits Content-Security-Policy (CSP)
        - Omits X-Content-Type-Options: nosniff
        - Omits X-Frame-Options (vulnerable to Clickjacking)
        - Omits Strict-Transport-Security (HSTS)
        """
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        # Insecure CORS: echoes incoming origin or wildcards with credentials allowed
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
        )
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight."""
        self._set_vulnerable_headers(status_code=204)

    def _parse_cookies(self) -> Dict[str, str]:
        cookies = {}
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            for item in cookie_header.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    cookies[k] = v
        return cookies

    def _get_current_user(self) -> Optional[Dict[str, Any]]:
        """Resolves current user from cookie or Authorization header."""
        token = None
        auth_header = self.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            cookies = self._parse_cookies()
            token = cookies.get("session_token")

        if not token:
            return None

        payload = verify_insecure_jwt(token)
        if payload and "user_id" in payload:
            return get_user_by_id(payload["user_id"])
        return None

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                return json.loads(body)
            except Exception:
                return {}
        return {}

    def _read_form_body(self) -> Dict[str, str]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(body)
            return {k: v[0] for k, v in parsed.items()}
        return {}

    def do_GET(self) -> None:
        """Route GET requests."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        try:
            if path == "/" or path == "/index.html":
                self._handle_home()
            elif path == "/login":
                self._handle_login_page()
            elif path == "/dashboard":
                self._handle_dashboard()
            elif path == "/search":
                # VULN: Reflected XSS
                self._handle_reflected_xss(query)
            elif path == "/tickets":
                # VULN: Stored XSS display
                self._handle_tickets_view()
            elif path == "/api/user/profile":
                # VULN: IDOR / BOLA
                self._handle_api_get_profile(query)
            elif path == "/api/documents":
                self._handle_api_list_documents()
            elif path == "/api/documents/download":
                # VULN: Path Traversal
                self._handle_path_traversal_download(query)
            elif path == "/api/tools/ping":
                # VULN: Command Injection (GET support)
                self._handle_command_injection(query.get("target", ["127.0.0.1"])[0])
            elif path == "/api/tools/fetch-url":
                # VULN: SSRF (GET support)
                self._handle_ssrf(query.get("url", ["http://127.0.0.1:8000/api/documents"])[0])
            elif path.startswith("/static/"):
                self._handle_static_files(path)
            else:
                self._set_vulnerable_headers(status_code=404)
                self.wfile.write(b"<h1>404 - Not Found</h1>")
        except Exception as e:
            # VULN: Verbose Error Disclosure (Stack trace leak)
            self._handle_error_disclosure(e)

    def do_POST(self) -> None:
        """Route POST requests."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            if path == "/login":
                self._handle_login_post()
            elif path == "/logout":
                self._handle_logout()
            elif path == "/tickets":
                # VULN: Stored XSS submission
                self._handle_tickets_post()
            elif path == "/api/user/profile":
                # VULN: Mass Assignment
                self._handle_api_update_profile()
            elif path == "/api/tools/ping":
                # VULN: Command Injection
                data = self._read_json_body() or self._read_form_body()
                target = data.get("target", "127.0.0.1")
                self._handle_command_injection(target)
            elif path == "/api/tools/fetch-url":
                # VULN: SSRF
                data = self._read_json_body() or self._read_form_body()
                url = data.get("url", "http://127.0.0.1:8000/")
                self._handle_ssrf(url)
            elif path == "/api/upload":
                # VULN: Unrestricted File Upload
                self._handle_unrestricted_upload()
            else:
                self._set_vulnerable_headers(status_code=404)
                self.wfile.write(b"<h1>404 - Route Not Found</h1>")
        except Exception as e:
            self._handle_error_disclosure(e)

    def do_PUT(self) -> None:
        """Route PUT requests."""
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/api/user/profile":
            self._handle_api_update_profile()
        else:
            self._set_vulnerable_headers(status_code=404)
            self.wfile.write(b"<h1>404 - Not Found</h1>")

    # =========================================================================
    # VULNERABILITY HANDLERS
    # =========================================================================

    def _handle_home(self) -> None:
        user = self._get_current_user()
        user_snippet = f"Logged in as: <strong>{user['username']}</strong> ({user['role']}) | <a href='/dashboard'>Dashboard</a> | <a href='/logout'>Logout</a>" if user else "<a href='/login'>Login to SWYNEX Portal</a>"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SWYNEX CloudPortal (Vulnerable Lab)</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .badge {{ background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🌐 SWYNEX CloudPortal <span class="badge">Vulnerable Lab Edition</span></h1>
        <p>Target Educational Environment for Defensive Web Security Review (Task 3).</p>
        <p>{user_snippet}</p>
    </div>
    <div class="card">
        <h3>Simulated Enterprise Endpoints & Vulnerabilities</h3>
        <ul>
            <li><strong>Command Injection (RCE):</strong> <code>POST /api/tools/ping</code> (Diagnostic Host Ping)</li>
            <li><strong>Server-Side Request Forgery (SSRF):</strong> <code>POST /api/tools/fetch-url</code> (Webhook URL Fetcher)</li>
            <li><strong>Reflected Cross-Site Scripting (XSS):</strong> <code>GET /search?q=&lt;script&gt;...</code></li>
            <li><strong>Stored Cross-Site Scripting (XSS):</strong> <code>GET/POST /tickets</code> (Support Feedback Board)</li>
            <li><strong>Path Traversal / Arbitrary File Read:</strong> <code>GET /api/documents/download?file=...</code></li>
            <li><strong>Unrestricted File Upload:</strong> <code>POST /api/upload</code> (Direct filesystem write)</li>
            <li><strong>BOLA / IDOR:</strong> <code>GET /api/user/profile?user_id=...</code> (Unchecked horizontal object lookup)</li>
            <li><strong>Mass Assignment:</strong> <code>PUT /api/user/profile</code> (Raw unvalidated role modification)</li>
            <li><strong>Broken Authentication / Weak JWT:</strong> Acceptance of <code>"alg": "none"</code> and hardcoded weak secrets.</li>
            <li><strong>Security Misconfiguration:</strong> CORS origin wildcarding and verbose exception stack disclosure.</li>
        </ul>
    </div>
</body>
</html>"""
        self._set_vulnerable_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_login_page(self) -> None:
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>SWYNEX Login</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
        .box { max-width: 400px; margin: auto; background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #475569; background: #0f172a; color: white; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #38bdf8; border: none; font-weight: bold; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="box">
        <h2>SWYNEX Portal Sign In</h2>
        <form method="POST" action="/login">
            <label>Username:</label>
            <input type="text" name="username" placeholder="e.g. alice, bob, admin" required>
            <label>Password:</label>
            <input type="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
        <p style="font-size: 12px; color: #94a3b8; margin-top: 16px;">
            Seed Accounts:<br>
            • <code>admin</code> : <code>AdminP@ss2026!</code> (Role: admin)<br>
            • <code>alice</code> : <code>AliceDevPassword99</code> (Role: developer)<br>
            • <code>bob</code> : <code>BobUserPass123</code> (Role: user)
        </p>
    </div>
</body>
</html>"""
        self._set_vulnerable_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_login_post(self) -> None:
        data = self._read_form_body() or self._read_json_body()
        username = data.get("username", "")
        password = data.get("password", "")

        # Vulnerable weak MD5 hashing
        pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        user = find_user_by_credentials(username, pwd_hash)

        if user:
            token = create_insecure_jwt({"user_id": user["id"], "username": user["username"], "role": user["role"]})
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            # VULNERABILITY: Insecure Cookie. Missing HttpOnly, Secure, SameSite
            self.send_header("Set-Cookie", f"session_token={token}; Path=/")
            self.end_headers()
        else:
            self._set_vulnerable_headers(status_code=401)
            self.wfile.write(b"<h1>401 - Invalid Credentials</h1><p><a href='/login'>Try again</a></p>")

    def _handle_logout(self) -> None:
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "session_token=; Path=/; Max-Age=0")
        self.end_headers()

    def _handle_dashboard(self) -> None:
        user = self._get_current_user()
        if not user:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - SWYNEX</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        a {{ color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ border: 1px solid #334155; padding: 8px; text-align: left; }}
        th {{ background: #334155; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Welcome, {user['full_name']} (@{user['username']})</h2>
        <p>Role: <strong>{user['role']}</strong> | Verified: <strong>{'Yes' if user['is_verified'] else 'No'}</strong></p>
        <p>Private API Token: <code>{user['api_token']}</code></p>
        <p><a href='/tickets'>Support Feedback Board</a> | <a href='/search?q=CloudPortal'>Search Utility</a> | <a href='/logout'>Sign Out</a></p>
    </div>

    <div class="card">
        <h3>Available Documents</h3>
        <p>Demonstrates Path Traversal vulnerability on download.</p>
        <ul>
            <li><a href="/api/documents/download?file=corporate_infrastructure_overview.pdf">corporate_infrastructure_overview.pdf</a></li>
            <li><a href="/api/documents/download?file=contractor_guidelines.txt">contractor_guidelines.txt</a></li>
            <li><a href="/api/documents/download?file=executive_q3_financial_audit.txt">executive_q3_financial_audit.txt</a></li>
        </ul>
    </div>
</body>
</html>"""
        self._set_vulnerable_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_reflected_xss(self, query: Dict[str, list[str]]) -> None:
        """VULNERABILITY: Reflected Cross-Site Scripting (XSS).

        The search parameter 'q' is reflected directly into the response without HTML escaping.
        """
        q = query.get("q", [""])[0]
        # Insecurely interpolating user input directly into HTML without html.escape()
        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body style="font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc;">
    <h2>Search Catalog</h2>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{q}" style="padding: 8px; width: 300px;">
        <button type="submit">Search</button>
    </form>
    <hr>
    <div>
        <h3>Search results for: {q}</h3>
        <p>No index items matched your search query.</p>
    </div>
</body>
</html>"""
        self._set_vulnerable_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_tickets_view(self) -> None:
        """VULNERABILITY: Stored Cross-Site Scripting (XSS).

        Customer feedback comments are rendered directly without HTML escaping.
        """
        tickets = get_all_tickets()
        rows_html = ""
        for t in tickets:
            # Insecurely interpolating unescaped title and comment from database
            rows_html += f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 6px; margin-bottom: 12px; border: 1px solid #334155;">
                <h4>{t['title']}</h4>
                <p>{t['comment']}</p>
                <small style="color: #94a3b8;">Author: {t['author_name']} | ID: {t['id']}</small>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Support Feedback Board</title></head>
<body style="font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc;">
    <h2>Support & Feedback Board (Stored XSS Lab)</h2>
    <div style="margin-bottom: 30px; background: #1e293b; padding: 16px; border-radius: 8px;">
        <h3>Submit Feedback</h3>
        <form method="POST" action="/tickets">
            <input type="text" name="title" placeholder="Subject" style="width: 100%; padding: 8px; margin-bottom: 8px;" required><br>
            <textarea name="comment" placeholder="Feedback / Comment" style="width: 100%; height: 80px; padding: 8px;" required></textarea><br>
            <button type="submit" style="padding: 8px 16px; background: #38bdf8; border: none; font-weight: bold; border-radius: 4px;">Submit</button>
        </form>
    </div>
    <h3>Recent Tickets:</h3>
    {rows_html}
</body>
</html>"""
        self._set_vulnerable_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def _handle_tickets_post(self) -> None:
        user = self._get_current_user()
        author_id = user["id"] if user else 3
        author_name = user["full_name"] if user else "Anonymous Contractor"

        data = self._read_form_body() or self._read_json_body()
        title = data.get("title", "Untitled Feedback")
        comment = data.get("comment", "")

        # Insecurely stored without sanitization or HTML encoding
        add_ticket(author_id, author_name, title, comment)

        self.send_response(302)
        self.send_header("Location", "/tickets")
        self.end_headers()

    def _handle_api_get_profile(self, query: Dict[str, list[str]]) -> None:
        """VULNERABILITY: Insecure Direct Object Reference (IDOR / BOLA).

        Allows any client to inspect ANY user profile simply by providing '?user_id=X'.
        Fails to verify whether the caller is authorized to view the requested record.
        """
        user_id_param = query.get("user_id")
        if not user_id_param:
            self._set_vulnerable_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Missing user_id parameter"}).encode("utf-8"))
            return

        try:
            target_id = int(user_id_param[0])
            user = get_user_by_id(target_id)
            if not user:
                self._set_vulnerable_headers("application/json", status_code=404)
                self.wfile.write(json.dumps({"error": "User not found"}).encode("utf-8"))
                return

            # Returns sensitive data (tokens, role, password hash) without authorization check
            self._set_vulnerable_headers("application/json")
            self.wfile.write(json.dumps(user).encode("utf-8"))
        except ValueError:
            self._set_vulnerable_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Invalid user_id"}).encode("utf-8"))

    def _handle_api_update_profile(self) -> None:
        """VULNERABILITY: Mass Assignment.

        Blindly applies all client-supplied keys to user model.
        Allows unprivileged users to escalate to 'role': 'admin' and 'is_verified': 1.
        """
        user = self._get_current_user()
        target_id = user["id"] if user else 3  # Fallback to test user if not authenticated

        payload = self._read_json_body()
        if not payload:
            self._set_vulnerable_headers("application/json", status_code=400)
            self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode("utf-8"))
            return

        success = update_user_profile_vulnerable(target_id, payload)
        if success:
            updated_user = get_user_by_id(target_id)
            self._set_vulnerable_headers("application/json")
            self.wfile.write(json.dumps({"status": "success", "user": updated_user}).encode("utf-8"))
        else:
            self._set_vulnerable_headers("application/json", status_code=500)
            self.wfile.write(json.dumps({"status": "error", "message": "Failed to update"}).encode("utf-8"))

    def _handle_api_list_documents(self) -> None:
        docs = get_all_documents()
        self._set_vulnerable_headers("application/json")
        self.wfile.write(json.dumps({"documents": docs}).encode("utf-8"))

    def _handle_path_traversal_download(self, query: Dict[str, list[str]]) -> None:
        """VULNERABILITY: Path Traversal / Arbitrary File Disclosure.

        Directly joins user input to base directory without canonical path verification.
        Allows retrieval of files such as /etc/passwd or application source files.
        """
        filename = query.get("file", [""])[0]
        if not filename:
            self._set_vulnerable_headers(status_code=400)
            self.wfile.write(b"<h1>400 - Missing file parameter</h1>")
            return

        # Insecure path resolution: os.path.join allows traversal if filename contains '../'
        target_path = os.path.join(DOCS_DIR, filename)

        if not os.path.exists(target_path):
            self._set_vulnerable_headers(status_code=404)
            self.wfile.write(f"<h1>404 - File '{filename}' not found</h1>".encode("utf-8"))
            return

        try:
            with open(target_path, "rb") as f:
                content = f.read()

            content_type = "text/plain; charset=utf-8"
            if filename.endswith(".pdf"):
                content_type = "application/pdf"
            self._set_vulnerable_headers(content_type)
            self.wfile.write(content)
        except Exception as e:
            self._handle_error_disclosure(e)

    def _handle_command_injection(self, target: str) -> None:
        """VULNERABILITY: OS Command Injection (Remote Code Execution).

        User-supplied target host is passed directly into a shell command string.
        """
        # Insecure concatenation into shell string
        command = f"ping -c 1 {target}"

        try:
            # shell=True enables command separators (; | && & ` $() )
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=5)
            response_data = {
                "command_executed": command,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }
            self._set_vulnerable_headers("application/json")
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
        except subprocess.TimeoutExpired:
            proc.kill()
            self._set_vulnerable_headers("application/json", status_code=504)
            self.wfile.write(json.dumps({"error": "Command execution timed out"}).encode("utf-8"))
        except Exception as e:
            self._handle_error_disclosure(e)

    def _handle_ssrf(self, target_url: str) -> None:
        """VULNERABILITY: Server-Side Request Forgery (SSRF).

        Fetches arbitrary URLs provided by client without restricting protocol scheme
        or validating internal private IP subnets (127.0.0.1, 169.254.169.254, etc.).
        """
        try:
            # Insecure: directly requests URL using urllib.request
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "SWYNEX-InternalWebhookFetcher/1.0"},
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                body = response.read(4096)  # Read initial chunk
                status = response.status
                headers_dict = dict(response.headers)

            self._set_vulnerable_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "target_url": target_url,
                        "status_code": status,
                        "response_headers": headers_dict,
                        "body_preview": body.decode("utf-8", errors="replace"),
                    }
                ).encode("utf-8")
            )
        except Exception as e:
            self._set_vulnerable_headers("application/json", status_code=502)
            self.wfile.write(
                json.dumps({"error": "SSRF Fetch Failed", "details": str(e)}).encode("utf-8")
            )

    def _handle_unrestricted_upload(self) -> None:
        """VULNERABILITY: Insecure / Unrestricted File Upload.

        1. Takes client-supplied filename without extension validation.
        2. Accepts executable or script extensions (.html, .py, .sh).
        3. Writes directly into public uploads directory.
        """
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))

        if "multipart/form-data" in content_type:
            # Parse multipart
            boundary = content_type.split("boundary=")[1].encode("utf-8")
            raw_body = self.rfile.read(content_length)

            # Extract basic parts
            filename = "uploaded_file.dat"
            file_data = b""

            for part in raw_body.split(b"--" + boundary):
                if b"filename=" in part:
                    header_part, body_part = part.split(b"\r\n\r\n", 1)
                    body_part = body_part.rstrip(b"\r\n--")
                    header_str = header_part.decode("utf-8", errors="replace")
                    for line in header_str.split("\r\n"):
                        if "filename=" in line:
                            filename = line.split("filename=")[1].strip('"')
                    file_data = body_part
                    break

            target_path = os.path.join(UPLOADS_DIR, filename)
            with open(target_path, "wb") as f:
                f.write(file_data)

            self._set_vulnerable_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "status": "success",
                        "filename": filename,
                        "saved_to": target_path,
                        "bytes_written": len(file_data),
                    }
                ).encode("utf-8")
            )
        else:
            filename = self.headers.get("X-Filename", "raw_upload.bin")
            file_data = self.rfile.read(content_length)
            target_path = os.path.join(UPLOADS_DIR, filename)
            with open(target_path, "wb") as f:
                f.write(file_data)

            self._set_vulnerable_headers("application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "status": "success",
                        "filename": filename,
                        "saved_to": target_path,
                        "bytes_written": len(file_data),
                    }
                ).encode("utf-8")
            )

    def _handle_static_files(self, path: str) -> None:
        rel_path = path[len("/static/") :]
        file_path = os.path.join(BASE_DIR, "static", rel_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            self._set_vulnerable_headers("text/css" if path.endswith(".css") else "text/javascript")
            self.wfile.write(content)
        else:
            self._set_vulnerable_headers(status_code=404)
            self.wfile.write(b"404 Static Not Found")

    def _handle_error_disclosure(self, exc: Exception) -> None:
        """VULNERABILITY: Verbose Error Disclosure.

        Dumps entire Python traceback, local environment, and paths to user on 500 error.
        """
        stack_trace = traceback.format_exc()
        self._set_vulnerable_headers("text/plain", status_code=500)
        error_dump = (
            f"500 INTERNAL SERVER ERROR\n"
            f"Exception: {str(exc)}\n"
            f"Environment: Python {sys.version} on {sys.platform}\n"
            f"Current Directory: {os.getcwd()}\n\n"
            f"Stack Trace:\n{stack_trace}\n"
        )
        self.wfile.write(error_dump.encode("utf-8"))


def run_server(port: int = 8000, host: str = "127.0.0.1") -> None:
    """Initializes DB and starts vulnerable server."""
    init_db()
    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    server_address = (host, port)
    httpd = HTTPServer(server_address, VulnerablePortalHandler)
    print(f"[*] SWYNEX Vulnerable Portal running at http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port=port_arg)
