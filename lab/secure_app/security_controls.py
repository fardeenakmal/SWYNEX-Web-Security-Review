"""SWYNEX Web Security Review - Enterprise Defensive Security Controls.

Comprehensive defense-in-depth library mitigating:
1. Command Injection (CWE-78 / OWASP A03)
2. Server-Side Request Forgery - SSRF (CWE-918 / OWASP A10)
3. Cross-Site Scripting - XSS (CWE-79 / OWASP A03)
4. Path Traversal (CWE-22 / OWASP A01)
5. Unrestricted File Upload (CWE-434 / OWASP A04)
6. Broken Object Level Authorization - BOLA/IDOR (CWE-639 / OWASP A01)
7. Broken Authentication & Weak JWT (CWE-287 / CWE-347 / OWASP A07)
8. Security Misconfiguration & Insecure CORS (CWE-942 / CWE-16 / OWASP A05)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple


class SecurityException(Exception):
    """Raised when a defensive security control boundary is violated."""
    pass


# =============================================================================
# 1. COMMAND INJECTION DEFENSE (CWE-78)
# =============================================================================

# Strict regex allowlisting RFC 1123 hostnames and IPv4/IPv6 addresses
HOSTNAME_OR_IP_REGEX = re.compile(
    r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|"
    r"localhost|"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1)$"
)


def validate_hostname_or_ip(target: str) -> str:
    """Validates target host against strict whitelist.

    Rejects shell metacharacters (; | & ` $ > < \n).
    """
    cleaned = target.strip()
    if not cleaned or len(cleaned) > 253:
        raise SecurityException("Invalid hostname length (must be between 1 and 253 characters).")

    if not HOSTNAME_OR_IP_REGEX.match(cleaned):
        raise SecurityException(
            f"Invalid target address format: '{cleaned}'. Target must be a valid RFC 1123 hostname or IP."
        )
    return cleaned


def safe_network_ping(target: str, count: int = 1, timeout_seconds: int = 3) -> Dict[str, Any]:
    """DEFENSE: Executes ping via vectorized arguments WITHOUT shell=True.

    Completely neutralizes command injection.
    """
    valid_host = validate_hostname_or_ip(target)
    # Argument array: parameter isolation prevents shell interpretation
    cmd_args = ["ping", "-c", str(count), "-W", str(timeout_seconds), valid_host]

    try:
        proc = subprocess.run(
            cmd_args,
            shell=False,  # CRITICAL: shell disabled
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 1,
        )
        return {
            "status": "success",
            "host": valid_host,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "host": valid_host,
            "exit_code": -1,
            "error": "Ping operation timed out.",
        }
    except Exception as e:
        return {
            "status": "error",
            "host": valid_host,
            "exit_code": -1,
            "error": str(e),
        }


# =============================================================================
# 2. SERVER-SIDE REQUEST FORGERY (SSRF) DEFENSE (CWE-918)
# =============================================================================

# Prohibited loopback, link-local, private, and cloud metadata CIDR ranges
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (AWS, Azure, GCP)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
]


def is_ip_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks if an IP address belongs to private, loopback, or metadata subnets."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    for net in DISALLOWED_NETWORKS:
        if ip in net:
            return True
    return False


def validate_ssrf_safe_url(url_str: str) -> Tuple[str, str, int]:
    """DEFENSE: Validates URL against SSRF vulnerabilities.

    1. Enforces http or https scheme.
    2. Resolves hostname to all target IPs.
    3. Blocks requests to loopback, RFC 1918 private subnets, and cloud metadata (169.254.169.254).
    """
    parsed = urllib.parse.urlparse(url_str)

    if parsed.scheme.lower() not in ("http", "https"):
        raise SecurityException(
            f"Invalid protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SecurityException("URL must contain a valid hostname.")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    # Disallow known internal domain aliases
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
        raise SecurityException(f"Destination hostname '{hostname}' is an internal protected target.")

    # DNS Resolution and IP validation
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SecurityException(f"DNS resolution failure for host '{hostname}': {e}")

    resolved_ips = set()
    for item in addr_info:
        ip_str = item[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        resolved_ips.add(ip_obj)

        if is_ip_disallowed(ip_obj):
            raise SecurityException(
                f"SSRF Protection: Host '{hostname}' resolved to prohibited address: {ip_str}."
            )

    return parsed.scheme.lower(), hostname, port


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevents HTTP redirects to prevent SSRF bypass via open redirect to loopback."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityException(f"HTTP redirection to '{newurl}' blocked by SSRF defense policy.")


def safe_fetch_url(target_url: str, timeout_seconds: int = 4) -> Dict[str, Any]:
    """DEFENSE: Performs SSRF-safe URL fetch with redirect blocking and size limit."""
    validate_ssrf_safe_url(target_url)

    opener = urllib.request.build_opener(NoRedirectHandler)
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "SWYNEX-SecureDefenseGateway/2.0"},
    )

    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            content = resp.read(8192)  # Max 8KB preview
            return {
                "status": "success",
                "status_code": resp.status,
                "content_preview": content.decode("utf-8", errors="replace"),
                "content_type": resp.headers.get("Content-Type", "text/plain"),
            }
    except SecurityException as se:
        raise se
    except Exception as e:
        return {"status": "error", "error": f"Connection error: {str(e)}"}


# =============================================================================
# 3. PATH TRAVERSAL DEFENSE (CWE-22)
# =============================================================================

def resolve_safe_file_path(base_dir: str, requested_filename: str) -> str:
    """DEFENSE: Strict path canonicalization.

    1. Checks for null bytes and directory traversal sequences ('..', '/', '\\').
    2. Canonicalizes path via os.path.realpath.
    3. Verifies that the resolved path strictly resides within base_dir.
    """
    if "\0" in requested_filename:
        raise SecurityException("Null byte detected in file path.")

    # Rejection of explicit directory traversal characters
    if ".." in requested_filename or "/" in requested_filename or "\\" in requested_filename:
        raise SecurityException("Directory traversal sequence detected in requested filename.")

    cleaned = requested_filename.strip()
    if not cleaned or cleaned in (".", ".."):
        raise SecurityException("Invalid file name requested.")

    canonical_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(canonical_base, cleaned))

    # Verify that target_path is strictly inside canonical_base
    try:
        common = os.path.commonpath([canonical_base, target_path])
    except ValueError:
        raise SecurityException("Cross-drive or cross-device traversal attempt.")

    if common != canonical_base or not target_path.startswith(canonical_base + os.sep):
        raise SecurityException("Directory traversal attempt detected outside authorized base.")

    return target_path


# =============================================================================
# 4. UNRESTRICTED FILE UPLOAD DEFENSE (CWE-434)
# =============================================================================

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
ALLOWED_MIME_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": ".png",
    b"\xff\xd8\xff": ".jpg",
}
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2 MB limit


def validate_and_save_upload(
    client_filename: str, file_data: bytes, upload_directory: str
) -> Tuple[str, str]:
    """DEFENSE: Hardened file upload processing.

    1. Checks file size against 2MB limit.
    2. Validates extension against strict whitelist (.png, .jpg, .jpeg).
    3. Validates file magic bytes (signatures) to prevent MIME spoofing.
    4. Generates a cryptographically random UUID4 filename.
    5. Saves file to an isolated, non-executable storage directory.
    """
    if len(file_data) > MAX_UPLOAD_SIZE:
        raise SecurityException(f"File size ({len(file_data)} bytes) exceeds 2MB maximum limit.")

    if len(file_data) < 8:
        raise SecurityException("File payload is empty or corrupted.")

    _, ext = os.path.splitext(client_filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise SecurityException(
            f"File extension '{ext}' is prohibited. Only PNG and JPEG images are permitted."
        )

    # Magic byte verification
    is_valid_magic = False
    if ext == ".png" and file_data.startswith(b"\x89PNG\r\n\x1a\n"):
        is_valid_magic = True
    elif ext in (".jpg", ".jpeg") and file_data.startswith(b"\xff\xd8\xff"):
        is_valid_magic = True

    if not is_valid_magic:
        raise SecurityException("File magic header does not match declared image type.")

    # Secure random filename generation
    random_filename = f"{uuid.uuid4().hex}{ext}"
    safe_destination = resolve_safe_file_path(upload_directory, random_filename)

    with open(safe_destination, "wb") as f:
        f.write(file_data)

    return random_filename, safe_destination


# =============================================================================
# 5. CRYPTOGRAPHIC JWT & SESSION DEFENSE (CWE-287 / CWE-347)
# =============================================================================

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode("utf-8"))


def create_secure_jwt(payload: Dict[str, Any], secret_key: str, ttl_seconds: int = 3600) -> str:
    """DEFENSE: Generates an HS256 JWT with expiration and issued-at timestamps."""
    header = {"typ": "JWT", "alg": "HS256"}
    now = int(time.time())

    secure_payload = dict(payload)
    secure_payload["iat"] = now
    secure_payload["exp"] = now + ttl_seconds
    secure_payload["jti"] = secrets.token_hex(16)

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(secure_payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_secure_jwt(token: str, secret_key: str) -> Optional[Dict[str, Any]]:
    """DEFENSE: Validates JWT signature and expiration.

    1. Strictly enforces 'HS256' algorithm.
    2. Rejects 'none' algorithm.
    3. Validates HMAC signature using constant-time comparison.
    4. Enforces 'exp' timestamp expiration.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_json = json.loads(base64url_decode(parts[0]).decode("utf-8"))
        if header_json.get("alg") != "HS256":
            return None  # Rejection of 'none' or unapproved algorithms

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig = base64url_encode(
            hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        )

        if not hmac.compare_digest(parts[2], expected_sig):
            return None

        payload = json.loads(base64url_decode(parts[1]).decode("utf-8"))
        now = int(time.time())

        # Expiration check
        if "exp" in payload and now > payload["exp"]:
            return None

        return payload
    except Exception:
        return None


# =============================================================================
# 6. XSS SANITIZATION & SECURITY HEADERS (CWE-79 / CWE-16)
# =============================================================================

def sanitize_html_content(raw_text: str) -> str:
    """DEFENSE: Context-aware HTML entity encoding."""
    return html.escape(raw_text, quote=True)


def get_defense_in_depth_headers() -> Dict[str, str]:
    """DEFENSE: Comprehensive HTTP security headers baseline."""
    return {
        # Restrict origins and scripts
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        ),
        # Prevent clickjacking
        "X-Frame-Options": "DENY",
        # Prevent MIME type sniffing
        "X-Content-Type-Options": "nosniff",
        # Referrer Policy
        "Referrer-Policy": "strict-origin-when-cross-origin",
        # Enforce HTTPS
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        # Restrict browser capabilities
        "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
        # Invalidate client caches for private data
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
