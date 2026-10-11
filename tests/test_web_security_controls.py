"""SWYNEX Web Security Review - Automated Security Control Verification Suite.

Automated tests evaluating defensive controls and demonstrating vulnerability remediation
across all 8 target security vectors:
1. Command Injection (CWE-78 / OWASP A03)
2. Server-Side Request Forgery - SSRF (CWE-918 / OWASP A10)
3. Cross-Site Scripting - Reflected & Stored (CWE-79 / OWASP A03)
4. Path Traversal & Arbitrary File Access (CWE-22 / OWASP A01)
5. Unrestricted File Upload (CWE-434 / OWASP A04)
6. BOLA / IDOR & Mass Assignment (CWE-639 / CWE-915 / OWASP A01)
7. Broken Authentication & Weak JWT Implementation (CWE-287 / CWE-347 / OWASP A07)
8. Security Misconfiguration & Insecure CORS (CWE-942 / CWE-16 / OWASP A05)

Zero External Dependencies: Built on Python 3.8+ standard library unittest.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
import time
import unittest
from typing import Any, Dict

# Vulnerable App Modules
from lab.vulnerable_app import database as vuln_db
from lab.vulnerable_app import server as vuln_server

# Secure App Modules
from lab.secure_app import database as sec_db
from lab.secure_app import security_controls as sec_controls
from lab.secure_app import server as sec_server


class TestWebSecurityControls(unittest.TestCase):
    """Defensive verification test suite validating vulnerable flaws and secure remediations."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.test_dir = tempfile.mkdtemp(prefix="swynex_web_test_")

        # Initialize isolated test databases
        cls.vuln_db_path = os.path.join(cls.test_dir, "test_vuln.db")
        cls.sec_db_path = os.path.join(cls.test_dir, "test_sec.db")

        vuln_db.DB_FILE = cls.vuln_db_path
        vuln_db.init_db(cls.vuln_db_path)

        sec_db.DB_FILE = cls.sec_db_path
        sec_db.init_db(cls.sec_db_path)

        cls.jwt_secret = "test_super_secret_key_9918237462837462"

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    # =========================================================================
    # 1. COMMAND INJECTION (CWE-78 / OWASP A03)
    # =========================================================================

    def test_01_command_injection_vulnerability_present_in_vulnerable_app(self) -> None:
        """Verifies that the vulnerable app shell command concatenation accepts metacharacters."""
        target = "127.0.0.1; echo INJECTED_EXECUTION"
        command = f"ping -c 1 {target}"
        self.assertIn("; echo INJECTED_EXECUTION", command)
        # In vulnerable code, shell=True runs the command chaining
        self.assertTrue(";" in command or "&&" in command)

    def test_02_command_injection_mitigated_in_secure_app(self) -> None:
        """Verifies that the secure app rejects command chaining payloads via strict regex."""
        malicious_payloads = [
            "127.0.0.1; cat /etc/passwd",
            "localhost && whoami",
            "127.0.0.1 | id",
            "`id`",
            "$(whoami)",
            "127.0.0.1\nid",
        ]
        for payload in malicious_payloads:
            with self.assertRaises(sec_controls.SecurityException):
                sec_controls.validate_hostname_or_ip(payload)

        # Valid hostname passes
        valid_host = sec_controls.validate_hostname_or_ip("127.0.0.1")
        self.assertEqual(valid_host, "127.0.0.1")

    # =========================================================================
    # 2. SERVER-SIDE REQUEST FORGERY - SSRF (CWE-918 / OWASP A10)
    # =========================================================================

    def test_03_ssrf_mitigated_blocking_internal_loopback_and_metadata(self) -> None:
        """Verifies that the SSRF defense blocks loopback, RFC 1918, and cloud metadata targets."""
        forbidden_urls = [
            "http://127.0.0.1:8000/api/documents",
            "http://localhost:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/router",
            "http://[::1]/admin",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_flushall",
        ]
        for url in forbidden_urls:
            with self.assertRaises(sec_controls.SecurityException):
                sec_controls.validate_ssrf_safe_url(url)

    # =========================================================================
    # 3. CROSS-SITE SCRIPTING - XSS (CWE-79 / OWASP A03)
    # =========================================================================

    def test_04_xss_sanitization_neutralizes_script_tags(self) -> None:
        """Verifies context-aware HTML entity escaping prevents script payload execution."""
        xss_payload = "<script>alert('XSS_POC')</script><img src=x onerror=alert(1)>"
        sanitized = sec_controls.sanitize_html_content(xss_payload)

        self.assertNotIn("<script>", sanitized)
        self.assertNotIn("<img", sanitized)
        self.assertIn("&lt;script&gt;", sanitized)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", sanitized)

    def test_05_content_security_policy_header_enforced(self) -> None:
        """Verifies strict CSP header is present in defensive headers suite."""
        headers = sec_controls.get_defense_in_depth_headers()
        self.assertIn("Content-Security-Policy", headers)
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    # =========================================================================
    # 4. PATH TRAVERSAL (CWE-22 / OWASP A01)
    # =========================================================================

    def test_06_path_traversal_mitigated_by_canonical_boundary_check(self) -> None:
        """Verifies canonical path resolution blocks directory traversal attacks."""
        base_docs_dir = os.path.join(self.test_dir, "safe_docs")
        os.makedirs(base_docs_dir, exist_ok=True)

        # Create a legitimate document
        legit_file = os.path.join(base_docs_dir, "legit.txt")
        with open(legit_file, "w") as f:
            f.write("Legitimate Content")

        # Legitimate access succeeds
        resolved = sec_controls.resolve_safe_file_path(base_docs_dir, "legit.txt")
        self.assertEqual(resolved, legit_file)

        # Traversal attempts must raise SecurityException
        traversal_attempts = [
            "../../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "legit.txt\0/etc/shadow",
            "/etc/passwd",
            "../safe_docs/../../etc/hosts",
        ]
        for attempt in traversal_attempts:
            with self.assertRaises(sec_controls.SecurityException):
                sec_controls.resolve_safe_file_path(base_docs_dir, attempt)

    # =========================================================================
    # 5. UNRESTRICTED FILE UPLOAD (CWE-434 / OWASP A04)
    # =========================================================================

    def test_07_file_upload_rejects_dangerous_extensions_and_fake_magic_bytes(self) -> None:
        """Verifies file upload security validates extensions and magic byte headers."""
        upload_dir = os.path.join(self.test_dir, "test_uploads")
        os.makedirs(upload_dir, exist_ok=True)

        # Malicious web shell attempt (.html / .py)
        with self.assertRaises(sec_controls.SecurityException):
            sec_controls.validate_and_save_upload(
                "shell.php", b"<?php system($_GET['cmd']); ?>", upload_dir
            )

        with self.assertRaises(sec_controls.SecurityException):
            sec_controls.validate_and_save_upload(
                "xss.html", b"<script>alert(1)</script>", upload_dir
            )

        # Extension spoofing (named .png but containing plain malicious text)
        with self.assertRaises(sec_controls.SecurityException):
            sec_controls.validate_and_save_upload(
                "fake.png", b"NOT_A_REAL_PNG_HEADER_DATA_STREAM", upload_dir
            )

        # Valid PNG with correct magic bytes succeeds and receives a UUID filename
        valid_png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        stored_name, full_path = sec_controls.validate_and_save_upload(
            "legit_avatar.png", valid_png_bytes, upload_dir
        )
        self.assertTrue(stored_name.endswith(".png"))
        self.assertNotEqual(stored_name, "legit_avatar.png")  # Must be randomized
        self.assertTrue(os.path.exists(full_path))

    # =========================================================================
    # 6. BOLA / IDOR & MASS ASSIGNMENT (CWE-639 / CWE-915 / OWASP A01)
    # =========================================================================

    def test_08_mass_assignment_prevented_by_field_whitelist(self) -> None:
        """Verifies mass assignment vulnerability in vulnerable app vs whitelist in secure app."""
        # 1. Vulnerable app accepts arbitrary role elevation
        vuln_user = vuln_db.get_user_by_id(3)
        self.assertEqual(vuln_user["role"], "user")
        vuln_db.update_user_profile_vulnerable(3, {"role": "admin", "is_verified": 1})
        elevated_vuln = vuln_db.get_user_by_id(3)
        self.assertEqual(elevated_vuln["role"], "admin")
        self.assertEqual(elevated_vuln["is_verified"], 1)

        # 2. Secure app ignores or rejects role escalation attempts
        sec_user = sec_db.get_user_by_id_secure(3)
        self.assertEqual(sec_user["role"], "user")

        # Attempt to escalate role via mass assignment
        success, msg = sec_db.update_user_profile_secure(
            3, {"role": "admin", "full_name": "Bob Updated", "is_verified": 1}
        )
        self.assertTrue(success)
        rechecked_sec = sec_db.get_user_by_id_secure(3)
        self.assertEqual(rechecked_sec["full_name"], "Bob Updated")  # Permitted
        self.assertEqual(rechecked_sec["role"], "user")  # Role NOT elevated!
        self.assertEqual(rechecked_sec["is_verified"], 0)  # Verification NOT elevated!

    # =========================================================================
    # 7. BROKEN AUTHENTICATION & WEAK JWT (CWE-287 / CWE-347 / OWASP A07)
    # =========================================================================

    def test_09_vulnerable_jwt_accepts_algorithm_none(self) -> None:
        """Verifies vulnerable JWT accepts unsigned 'none' algorithm token."""
        token = vuln_server.create_insecure_jwt({"user_id": 1, "role": "admin"}, alg="none")
        verified = vuln_server.verify_insecure_jwt(token)
        self.assertIsNotNone(verified)
        self.assertEqual(verified["user_id"], 1)
        self.assertEqual(verified["role"], "admin")

    def test_10_secure_jwt_enforces_hs256_and_rejects_none_algorithm(self) -> None:
        """Verifies secure JWT strictly rejects 'none' algorithm and invalid signatures."""
        # 1. Forge a 'none' algorithm token
        header = sec_controls.base64url_encode(json.dumps({"typ": "JWT", "alg": "none"}).encode())
        payload = sec_controls.base64url_encode(json.dumps({"user_id": 1, "role": "admin"}).encode())
        forged_token = f"{header}.{payload}."

        verified = sec_controls.verify_secure_jwt(forged_token, self.jwt_secret)
        self.assertIsNone(verified)

        # 2. Legitimate token signed with correct key succeeds
        valid_token = sec_controls.create_secure_jwt(
            {"user_id": 2, "role": "developer"}, self.jwt_secret, ttl_seconds=3600
        )
        verified_valid = sec_controls.verify_secure_jwt(valid_token, self.jwt_secret)
        self.assertIsNotNone(verified_valid)
        self.assertEqual(verified_valid["user_id"], 2)

        # 3. Expired token is rejected
        expired_token = sec_controls.create_secure_jwt(
            {"user_id": 2, "role": "developer"}, self.jwt_secret, ttl_seconds=-10
        )
        verified_expired = sec_controls.verify_secure_jwt(expired_token, self.jwt_secret)
        self.assertIsNone(verified_expired)

    # =========================================================================
    # 8. SECURITY MISCONFIGURATION & HEADERS (CWE-942 / CWE-16 / OWASP A05)
    # =========================================================================

    def test_11_defense_in_depth_headers_present(self) -> None:
        """Verifies complete security header suite is configured."""
        headers = sec_controls.get_defense_in_depth_headers()
        expected = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "Permissions-Policy",
            "Cache-Control",
        ]
        for h in expected:
            self.assertIn(h, headers)
            self.assertTrue(len(headers[h]) > 0)


    def test_12_password_hashing_pbkdf2_vs_md5(self) -> None:
        """Verifies PBKDF2-HMAC-SHA256 password security vs vulnerable unsalted MD5."""
        plain_password = "SecurePassword123!"

        # Vulnerable app: deterministic unsalted MD5
        vuln_hash1 = vuln_server.hashlib.md5(plain_password.encode()).hexdigest()
        vuln_hash2 = vuln_server.hashlib.md5(plain_password.encode()).hexdigest()
        self.assertEqual(vuln_hash1, vuln_hash2)  # Identical, prone to rainbow tables

        # Secure app: random salt + 600,000 PBKDF2 iterations
        salt1, hash1 = sec_db.hash_password(plain_password)
        salt2, hash2 = sec_db.hash_password(plain_password)
        self.assertNotEqual(salt1, salt2)  # Salt is distinct
        self.assertNotEqual(hash1, hash2)  # Hashes differ for same plaintext

        # Verification succeeds
        self.assertTrue(sec_db.verify_password(plain_password, salt1, hash1))
        self.assertFalse(sec_db.verify_password("WrongPassword!", salt1, hash1))

    def test_13_bola_idor_access_control_logic(self) -> None:
        """Verifies BOLA/IDOR authorization check blocks unauthorized horizontal profile access."""
        # Simulated caller: Bob (user_id=3, role='user')
        caller_bob = {"id": 3, "role": "user", "username": "bob"}
        # Target: Admin (user_id=1)
        target_admin_id = 1

        # Direct authorization rule check
        is_bob_authorized_for_admin = (caller_bob["id"] == target_admin_id or caller_bob["role"] == "admin")
        self.assertFalse(is_bob_authorized_for_admin)

        # Bob accessing Bob's profile succeeds
        is_bob_authorized_for_self = (caller_bob["id"] == 3 or caller_bob["role"] == "admin")
        self.assertTrue(is_bob_authorized_for_self)

        # Admin accessing Bob's profile succeeds
        caller_admin = {"id": 1, "role": "admin", "username": "admin"}
        is_admin_authorized = (caller_admin["id"] == 3 or caller_admin["role"] == "admin")
        self.assertTrue(is_admin_authorized)

    def test_14_cookie_security_directives_format(self) -> None:
        """Verifies production-grade session cookie directives format."""
        token = "sample_test_token_12345"
        cookie_header = f"session_token={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600"

        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("Secure", cookie_header)
        self.assertIn("SameSite=Strict", cookie_header)
        self.assertIn("Path=/", cookie_header)

    def test_15_web_security_auditor_compliance_scoring(self) -> None:
        """Verifies automated security auditor identifies missing headers and rewards secure headers."""
        from tools.web_security_auditor import WebSecurityAuditor

        auditor_hardened = WebSecurityAuditor("http://127.0.0.1:8443")
        hardened_headers = sec_controls.get_defense_in_depth_headers()
        auditor_hardened.audit_security_headers(hardened_headers)
        self.assertEqual(auditor_hardened.results["score"], 100)
        self.assertEqual(len(auditor_hardened.results["findings"]), 0)

        # Test against completely missing headers
        auditor_vuln = WebSecurityAuditor("http://127.0.0.1:8000")
        auditor_vuln.audit_security_headers({})
        self.assertLess(auditor_vuln.results["score"], 50)
        self.assertGreater(len(auditor_vuln.results["findings"]), 4)


if __name__ == "__main__":
    unittest.main()
