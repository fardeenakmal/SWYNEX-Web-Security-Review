# Security Finding Dossier: SEC-WEB-007

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-007`
- **Title:** Broken Authentication & Weak JWT Signing Implementation
- **Vulnerability Category:** OWASP Top 10:2021 – A07: Identification and Authentication Failures
- **CWE Identifier:** CWE-287: Improper Authentication & CWE-347: Improper Verification of Cryptographic Signature
- **CVSS v3.1 Base Score:** **8.1 (High)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (Session & JWT Engine)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The session authentication system implemented multiple cryptographic deficiencies:

1. **Algorithm "none" Acceptance:** In `verify_insecure_jwt()`, if the token header specified `"alg": "none"`, the server bypassed HMAC signature verification entirely and accepted unsigned payloads.
2. **Weak Signing Key:** The server signed tokens with a static, trivial secret (`"weak_lab_secret_key_123"`), susceptible to offline dictionary cracking.
3. **No Expiration Enforcement:** Issued tokens lacked the `exp` claim, remaining valid indefinitely.
4. **Weak Password Hashing:** User passwords were stored using unsalted MD5 digests.
5. **Insecure Cookie Directives:** The `session_token` cookie was emitted without `HttpOnly`, `Secure`, and `SameSite` flags.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Forged Unsigned JWT Token
```python
# Constructing unsigned JWT with algorithm none
header = '{"typ": "JWT", "alg": "none"}'
payload = '{"user_id": 1, "username": "admin", "role": "admin"}'
forged_token = f"{b64(header)}.{b64(payload)}."
```

### Request with Forged Token
```http
GET /api/user/profile?user_id=1 HTTP/1.1
Host: 127.0.0.1:8000
Cookie: session_token=eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJub25lIn0.eyJ1c2VyX2lkIjogMSwgInJvbGUiOiAiYWRtaW4ifQ.
```
**Outcome:** The server authenticated the request as `admin`, allowing full administrative access.

---

## 💥 Impact Analysis
- **Universal Authentication Bypass:** Any actor can forge administrative credentials without knowing the secret key.
- **Session Replay & Theft:** Absence of expiration and `HttpOnly` flags facilitates token exfiltration via client-side script injection.

---

## 🛡️ Remediation & Defensive Implementation

1. **Strict Algorithm Enforcement:** Enforce `HS256` and reject `"none"` or unapproved algorithms.
2. **Cryptographically Secure Keys:** Use 256-bit cryptographically random signing secrets.
3. **Expiration & Claim Validation:** Enforce `exp` and `iat` claims.
4. **PBKDF2 Password Storage:** Upgrade to salted PBKDF2-HMAC-SHA256 (600,000 iterations).
5. **Hardened Cookie Directives:** Enforce `HttpOnly; Secure; SameSite=Strict; Path=/`.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
if alg == "none":
    return payload_json  # Insecurely accepts unsigned token!
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
def verify_secure_jwt(token: str, secret_key: str) -> Optional[Dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header = json.loads(base64url_decode(parts[0]))
    if header.get("alg") != "HS256":
        return None  # Rejection of algorithm 'none'

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = base64url_encode(hmac.new(secret_key.encode(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(parts[2], expected_sig):
        return None

    payload = json.loads(base64url_decode(parts[1]))
    if "exp" in payload and time.time() > payload["exp"]:
        return None
    return payload
```

---

## ✅ Verification
Validated via automated test cases `test_09_vulnerable_jwt_accepts_algorithm_none`, `test_10_secure_jwt_enforces_hs256_and_rejects_none_algorithm`, `test_12_password_hashing_pbkdf2_vs_md5`, and `test_14_cookie_security_directives_format` in `tests/test_web_security_controls.py`.
