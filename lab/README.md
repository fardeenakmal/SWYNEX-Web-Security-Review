# SWYNEX Web Security Laboratory

> **Authorized Local Testbed:** `SWYNEX-Web-Security-Review`  
> **Target Environment:** Localhost / Isolated Container (`127.0.0.1`)  
> **Scope:** Intentionally vulnerable application (`lab/vulnerable_app/`) paired with a defense-in-depth hardened reference application (`lab/secure_app/`).

---

## 🏗️ Architecture Overview

The SWYNEX Web Security Review lab implements a realistic enterprise platform (**SWYNEX CloudPortal**) with dual execution targets:

1. **`lab/vulnerable_app/` (Port 8000):**
   - Implements classical and modern OWASP Top 10 vulnerabilities.
   - Highlights design, implementation, and configuration defects.
   - Serves as the audit subject for defensive security evaluation.

2. **`lab/secure_app/` (Port 8443):**
   - Demonstrates production-grade mitigations and defense-in-depth security controls.
   - Implements strict cryptographic standards, parameterized execution, SSRF IP blocking, path canonicalization, strict input validation, and security headers.

---

## 🚀 Running the Lab Applications

### Prerequisites
Both applications are engineered with the standard library of **Python 3.8+**. No third-party packages are required.

### 1. Starting the Vulnerable Portal (Port 8000)
```bash
python3 -m lab.vulnerable_app.server
# Or specify a custom port:
python3 -m lab.vulnerable_app.server 8000
```
- Web Interface: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

### 2. Starting the Hardened Secure Portal (Port 8443)
```bash
python3 -m lab.secure_app.server
# Or specify a custom port:
python3 -m lab.secure_app.server 8443
```
- Web Interface: [http://127.0.0.1:8443/](http://127.0.0.1:8443/)

---

## 👥 Seed Testbed Accounts

The following credentials are pre-seeded in both databases (`vulnerable_portal.db` and `secure_portal.db`):

| Username | Plaintext Password | Assigned Role | Permissions & Notes |
| :--- | :--- | :--- | :--- |
| **`admin`** | `AdminP@ss2026!` | `admin` | Chief Security Officer; access to all confidential records and audit logs. |
| **`alice`** | `AliceDevPassword99` | `developer` | Lead Cloud Architect; developer access to architecture specifications. |
| **`bob`** | `BobUserPass123` | `user` | External contractor; unprivileged standard account. |

---

## 🔍 Vulnerability Matrix & Endpoint Reference

| Threat Vector | Affected Endpoint | Vulnerable Behavior | Hardened Defensive Control |
| :--- | :--- | :--- | :--- |
| **Command Injection (RCE)** | `POST /api/tools/ping` | Passes user string to shell (`shell=True`) | Strict RFC 1123 regex; vectorized subprocess (`shell=False`) |
| **Server-Side Request Forgery** | `POST /api/tools/fetch-url` | Fetches any URL via `urllib.request` | DNS resolution check; private/loopback/cloud IP blocking; redirect blocking |
| **Reflected XSS** | `GET /search?q=...` | Direct unescaped query string reflection | Context-aware HTML entity encoding (`html.escape`) + CSP |
| **Stored XSS** | `POST /tickets`, `GET /tickets` | Unsanitized comment rendering in DOM | Strict HTML escaping on output; Content-Security-Policy |
| **Path Traversal** | `GET /api/documents/download?file=...` | Joins raw input without realpath check | `os.path.realpath` canonicalization and base boundary check |
| **Unrestricted File Upload** | `POST /api/upload` | Direct disk write with client filename | Extension whitelist (`.png`, `.jpg`), magic byte verification, UUID naming |
| **BOLA / IDOR** | `GET /api/user/profile?user_id=...` | Returns any user's profile and token | Contextual caller identity check and RBAC validation |
| **Mass Assignment** | `PUT /api/user/profile` | Blind update of all JSON fields | Strict DTO allowlisting (`full_name`, `bio` only) |
| **Weak JWT & Cookies** | Global Session Management | Accepts `alg: "none"`; weak secret | HS256 algorithm enforcement; `HttpOnly; Secure; SameSite=Strict` |
| **Security Misconfiguration** | HTTP Response Headers | Wildcard CORS credentials; stack traces | Explicit CORS allowlist; 6+ security headers; generic errors |

---

## 🛡️ Automated Verification

To run the automated security control verification test suite against both applications:
```bash
python3 -m unittest tests/test_web_security_controls.py -v
```

To run the automated defensive security auditor CLI tool:
```bash
python3 -m tools.web_security_auditor --target http://127.0.0.1:8000
python3 -m tools.web_security_auditor --target http://127.0.0.1:8443
```

