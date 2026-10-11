# Security Finding Dossier: SEC-WEB-003

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-003`
- **Title:** Stored & Reflected Cross-Site Scripting (XSS)
- **Vulnerability Category:** OWASP Top 10:2021 – A03: Injection
- **CWE Identifier:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **CVSS v3.1 Base Score:** **6.1 (Medium)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (`GET /search`, `GET/POST /tickets`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The application exhibits two distinct variants of Cross-Site Scripting:

1. **Reflected XSS:** The catalog search utility at `GET /search?q=` directly concatenates user-supplied search parameters into the HTML response body without entity escaping.
2. **Stored XSS:** The feedback ticket submission form at `POST /tickets` stores user-provided text in the SQLite database without validation or sanitization. When tickets are listed at `GET /tickets`, raw comment HTML is inserted into the DOM.

Because the vulnerable server does not supply a `Content-Security-Policy` (CSP) header, injected scripts execute without browser hindrance.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Reflected Payload
```http
GET /search?q=%3Cscript%3Ealert(%27SWYNEX-XSS-POC%27)%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:8000
```

### Reflected Response Body
```html
<div>
    <h3>Search results for: <script>alert('SWYNEX-XSS-POC')</script></h3>
    <p>No index items matched your search query.</p>
</div>
```

---

## 💥 Impact Analysis
- **Session Hijacking:** Unauthorized execution of JavaScript allows adversaries to exfiltrate ambient session tokens.
- **Defacement & Phishing:** Attacker can alter page layout, render fake login modals, or redirect users to malicious domains.
- **Client-Side State Modification:** Malicious actions triggered on behalf of authenticated administrators or operators.

---

## 🛡️ Remediation & Defensive Implementation

1. **Context-Aware Output Encoding:** Apply `html.escape(text, quote=True)` to all user-controlled values before rendering into HTML templates.
2. **Content Security Policy (CSP):** Deploy strict HTTP response headers restricting script execution to origin-bound scripts (`script-src 'self'`).

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
html_content = f"<h3>Search results for: {q}</h3>"
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
def sanitize_html_content(raw_text: str) -> str:
    return html.escape(raw_text, quote=True)

# Applied to template rendering:
safe_q = sanitize_html_content(q)
html_content = f"<h3>Search results for: {safe_q}</h3>"
```

---

## ✅ Verification
Validated via automated test cases `test_04_xss_sanitization_neutralizes_script_tags` and `test_05_content_security_policy_header_enforced` in `tests/test_web_security_controls.py`.
