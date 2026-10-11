# Security Finding Dossier: SEC-WEB-008

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-008`
- **Title:** Insecure CORS Policy & Security Misconfiguration
- **Vulnerability Category:** OWASP Top 10:2021 – A05: Security Misconfiguration
- **CWE Identifier:** CWE-942: Permissive Cross-Domain Policy with Untrusted Domains & CWE-16: Configuration
- **CVSS v3.1 Base Score:** **6.5 (Medium)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (Global Response Pipeline & Error Handling)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The application's global response pipeline suffered from configuration defects across three areas:

1. **Insecure CORS Policy:** The server returned `Access-Control-Allow-Origin: *` or dynamically echoed unvalidated client `Origin` headers while simultaneously enabling `Access-Control-Allow-Credentials: true`. This allows malicious third-party websites visited by authenticated users to issue cross-origin requests and read sensitive JSON responses.
2. **Missing Essential Security Headers:** The application omitted standard defense-in-depth headers:
   - `Content-Security-Policy` (CSP)
   - `X-Frame-Options` (Clickjacking defense)
   - `X-Content-Type-Options: nosniff` (MIME confusion defense)
   - `Strict-Transport-Security` (HSTS)
   - `Referrer-Policy`
3. **Verbose Information Disclosure:** Unhandled 500 exceptions emitted full Python tracebacks, revealing internal filesystem paths, runtime versions, and active modules.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### 1. Insecure CORS Reflection
```http
OPTIONS /api/user/profile HTTP/1.1
Host: 127.0.0.1:8000
Origin: https://malicious-adversary.com
```

### Vulnerable Server Response
```http
HTTP/1.0 204 No Content
Access-Control-Allow-Origin: https://malicious-adversary.com
Access-Control-Allow-Credentials: true
```

### 2. Error Traceback Leakage
```
500 INTERNAL SERVER ERROR
Exception: invalid literal for int() with base 10: 'invalid_str'
Environment: Python 3.14.8 on linux
Current Directory: /home/fardeenakmal/Desktop/SWYNEX/task 3
Stack Trace:
Traceback (most recent call last):
  File ".../lab/vulnerable_app/server.py", line 224, in do_GET
    target_id = int(user_id_param[0])
```

---

## 💥 Impact Analysis
- **Cross-Origin Data Exfiltration:** Hostile external websites read authenticated API responses.
- **Clickjacking Susceptibility:** Framing allows UI redress attacks.
- **Reconnaissance Acceleration:** Internal stack traces disclose underlying software stack and file layout.

---

## 🛡️ Remediation & Defensive Implementation

1. **CORS Allowlisting:** Reject wildcard origins when credentials are enabled. Restrict CORS origins strictly to an authorized whitelist.
2. **Complete Security Headers Baseline:** Apply standard HTTP security headers on all responses.
3. **Sanitized Generic Errors:** Replace verbose tracebacks with sanitized generic error bodies containing unique UUID correlation IDs.

### Code Comparison

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
def get_defense_in_depth_headers() -> Dict[str, str]:
    return {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
```

---

## ✅ Verification
Validated via automated test cases `test_11_defense_in_depth_headers_present` and `test_15_web_security_auditor_compliance_scoring` in `tests/test_web_security_controls.py`.

