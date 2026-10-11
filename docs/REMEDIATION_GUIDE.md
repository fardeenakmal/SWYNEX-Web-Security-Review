# SWYNEX Technologies - Web Security Remediation & Developer Guide

> **Document Classification:** Internal Engineering Standard  
> **Target Audience:** Backend Developers, DevOps Engineers, Application Architects  
> **Author:** Fardeen Akmal (`fardeenakmal123@gmail.com`) - SWYNEX Technologies  
> **Associated Deliverables:** `lab/vulnerable_app/` vs. `lab/secure_app/`  

---

## 1. Developer Security Objectives

This guide provides concrete, side-by-side code diffs and architectural patterns to eliminate the top web application vulnerabilities identified during the SWYNEX Web Security Review.

Every pattern documented here follows the principle of **Defense-in-Depth**: relying on multiple complementary layers of security controls rather than a single check.

---

## 2. Side-by-Side Remediation Patterns

### 2.1 Remediating OS Command Injection (CWE-78)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: String formatting passed directly into shell interpreter
target = data.get("target")
command = f"ping -c 1 {target}"
proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
```
*Why this fails:* Setting `shell=True` invokes `/bin/sh` or `cmd.exe`. Metacharacters such as `;`, `&&`, or `|` allow attackers to append arbitrary operating system commands.

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
# DEFENSE: Strict RFC 1123 hostname regex + shell=False vectorized arguments
HOSTNAME_REGEX = re.compile(r"^(?:(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

def safe_network_ping(target: str) -> dict:
    if not HOSTNAME_REGEX.match(target.strip()):
        raise SecurityException("Invalid hostname format.")

    # Isolated argument array ensures target cannot be interpreted as command syntax
    cmd_args = ["ping", "-c", "1", "-W", "3", target.strip()]
    proc = subprocess.run(cmd_args, shell=False, capture_output=True, timeout=4)
    return {"status": "success", "stdout": proc.stdout}
```

---

### 2.2 Remediating Server-Side Request Forgery (SSRF) (CWE-918)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: Direct network fetch without scheme or target IP validation
req = urllib.request.Request(target_url)
with urllib.request.urlopen(req) as resp:
    data = resp.read()
```
*Why this fails:* Attackers can request loopback services (`127.0.0.1:8000`), local databases (`localhost:6379`), or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`).

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
# DEFENSE: DNS pre-resolution + IP range filtering + redirect suppression
def validate_ssrf_safe_url(url_str: str):
    parsed = urllib.parse.urlparse(url_str)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SecurityException("Only HTTP/HTTPS permitted.")

    # Resolve hostname to all destination IP addresses
    addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or 80)
    for item in addr_info:
        ip = ipaddress.ip_address(item[4][0])
        # Disallow loopback, private RFC 1918, link-local metadata, or multicast
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise SecurityException(f"Access to network address {ip} is prohibited.")

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityException("HTTP redirects blocked to prevent SSRF bypass.")
```

---

### 2.3 Remediating Cross-Site Scripting (XSS) (CWE-79)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: Direct string interpolation into HTML output
html_output = f"<h3>Search results for: {user_input}</h3>"
```
*Why this fails:* Malicious `<script>` tags, event handlers (`<img onerror=...>`), or SVG vectors execute within the victim's browser context.

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
# DEFENSE 1: Context-aware HTML entity encoding
safe_html = html.escape(user_input, quote=True)
html_output = f"<h3>Search results for: {safe_html}</h3>"

# DEFENSE 2: Strict Content-Security-Policy (CSP) HTTP Header
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
)
```

---

### 2.4 Remediating Path Traversal (CWE-22)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: os.path.join resolves relative '../' sequences outside base
target_path = os.path.join(DOCS_DIR, requested_filename)
with open(target_path, "rb") as f:
    content = f.read()
```
*Why this fails:* If `requested_filename` contains `../../../../etc/passwd`, `os.path.join` resolves to files outside the intended root.

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
# DEFENSE: Reject traversal tokens + canonical realpath boundary check
def resolve_safe_file_path(base_dir: str, requested_filename: str) -> str:
    if "\0" in requested_filename:
        raise SecurityException("Null byte detected.")
    if ".." in requested_filename or "/" in requested_filename or "\\" in requested_filename:
        raise SecurityException("Directory traversal sequences prohibited.")

    canonical_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(canonical_base, requested_filename.strip()))

    # Verify that target strictly resides inside the authorized base folder
    if not target_path.startswith(canonical_base + os.sep):
        raise SecurityException("Access outside safe boundary denied.")
    return target_path
```

---

### 2.5 Remediating Unrestricted File Upload (CWE-434)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: Trusts client-supplied filename and writes raw data to web root
destination = os.path.join(UPLOADS_DIR, form_filename)
with open(destination, "wb") as f:
    f.write(file_data)
```
*Why this fails:* Uploading `.html` or `.php` allows web shell execution or stored XSS execution.

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
MAX_SIZE = 2 * 1024 * 1024  # 2MB

def validate_and_save_upload(client_filename: str, data: bytes, upload_dir: str):
    if len(data) > MAX_SIZE:
        raise SecurityException("Exceeds 2MB limit.")

    _, ext = os.path.splitext(client_filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise SecurityException("File extension not permitted.")

    # Magic byte signature check
    if ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SecurityException("Invalid PNG magic bytes.")

    # Cryptographically random UUID naming (avoids collisions and script execution)
    safe_filename = f"{uuid.uuid4().hex}{ext}"
    dest = resolve_safe_file_path(upload_dir, safe_filename)
    with open(dest, "wb") as f:
        f.write(data)
    return safe_filename, dest
```

---

### 2.6 Remediating BOLA / IDOR & Mass Assignment (CWE-639 / CWE-915)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: IDOR - trusts user_id without caller ownership check
user = get_user_by_id(request.args.get("user_id"))

# FLAW: Mass Assignment - blindly updates all payload keys
set_clauses = [f"{k} = ?" for k in payload.keys()]
cursor.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", list(payload.values()) + [user_id])
```

#### ✅ Hardened Implementation (`lab/secure_app/server.py` & `database.py`)
```python
# DEFENSE 1: Contextual identity verification (IDOR / BOLA)
if caller["id"] != requested_id and caller["role"] != "admin":
    raise SecurityException("Forbidden: Cannot view other users' profiles.")

# DEFENSE 2: Strict Data Transfer Object (DTO) Allowlisting (Mass Assignment)
ALLOWED_UPDATE_FIELDS = {"full_name", "bio"}

def update_user_profile_secure(user_id: int, fields: dict):
    safe_updates = {k: v for k, v in fields.items() if k in ALLOWED_UPDATE_FIELDS}
    if not safe_updates:
        return False, "No permitted fields provided."

    set_clauses = [f"{k} = ?" for k in safe_updates.keys()]
    values = list(safe_updates.values()) + [user_id]
    cursor.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", values)
    return True, "Profile updated."
```

---

### 2.7 Remediating Broken Authentication & Weak JWTs (CWE-287 / CWE-347)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: Accepts 'none' algorithm and ignores expiration
if alg == "none":
    return payload  # Accepts unsigned forged token!
```

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
def verify_secure_jwt(token: str, secret_key: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header = json.loads(base64url_decode(parts[0]))
    if header.get("alg") != "HS256":  # Strict algorithm enforcement
        return None

    # Constant-time signature verification
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = base64url_encode(hmac.new(secret_key.encode(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(parts[2], expected_sig):
        return None

    payload = json.loads(base64url_decode(parts[1]))
    if "exp" in payload and time.time() > payload["exp"]:  # Expiration enforcement
        return None
    return payload
```

---

### 2.8 Remediating Security Misconfiguration & Insecure CORS (CWE-942 / CWE-16)

#### ❌ Vulnerable Implementation (`lab/vulnerable_app/server.py`)
```python
# FLAW: Permissive wildcard CORS with credentials; no security headers
response.headers["Access-Control-Allow-Origin"] = "*"
response.headers["Access-Control-Allow-Credentials"] = "true"
```

#### ✅ Hardened Implementation (`lab/secure_app/security_controls.py`)
```python
# DEFENSE: Restricted CORS origin whitelist + complete security header baseline
ALLOWED_ORIGINS = {"https://cloudportal.swynex.com", "http://127.0.0.1:8443"}

def apply_security_headers(handler, req_origin: str):
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    }
    for k, v in headers.items():
        handler.send_header(k, v)

    if req_origin in ALLOWED_ORIGINS:
        handler.send_header("Access-Control-Allow-Origin", req_origin)
        handler.send_header("Access-Control-Allow-Credentials", "true")
        handler.send_header("Vary", "Origin")
```

---

## 3. DevSecOps Verification Checklist

Developers must run the following checks prior to submitting code to production:

- [x] **Subprocess Calls:** Never pass `shell=True`. Always pass command arguments as an array (`["cmd", "arg1"]`).
- [x] **SSRF Protection:** Pre-resolve DNS and assert destination IP is not loopback, private, or metadata before requesting external URLs.
- [x] **User Inputs:** Encode dynamic content using `html.escape()`. Maintain strict CSP.
- [x] **File Systems:** Verify paths with `os.path.realpath()` and ensure destination starts with `base_dir + os.sep`.
- [x] **Uploads:** Enforce extension allowlist and check magic bytes. Rename files with UUIDs.
- [x] **Authorization:** Validate session user against the resource owner for all read/write endpoints.
- [x] **Payload Binding:** Use explicit DTO allowlists for updates; never bind unvalidated JSON to database models.
- [x] **Cookies:** Set `HttpOnly; Secure; SameSite=Strict` on all sensitive authentication tokens.
- [x] **Automated Tests:** Execute `python3 -m unittest tests/test_web_security_controls.py` ensuring 100% pass rate.

