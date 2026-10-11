# Security Finding Dossier: SEC-WEB-006

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-006`
- **Title:** BOLA / IDOR & Mass Assignment Privilege Escalation
- **Vulnerability Category:** OWASP Top 10:2021 – A01: Broken Access Control & OWASP API Security: API1 & API3
- **CWE Identifier:** CWE-639: Authorization Bypass Through User-Controlled Key & CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- **CVSS v3.1 Base Score:** **8.8 (Critical)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Affected Component:** `lab/vulnerable_app/server.py` & `database.py` (`GET/PUT /api/user/profile`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The user management profile API exhibits two critical access control flaws:

1. **Insecure Direct Object Reference (BOLA / IDOR):** At `GET /api/user/profile?user_id=X`, the backend retrieves records solely based on the supplied query integer. The service fails to cross-reference the requesting caller's session against the target ID, allowing an unprivileged contractor (Bob, `user_id=3`) to retrieve full profile details and sensitive API tokens belonging to the Administrator (`user_id=1`).
2. **Mass Assignment:** At `PUT /api/user/profile`, the backend directly unpacks incoming JSON keys into SQL update clauses (`UPDATE users SET {k} = ? ...`). An attacker can inject privileged schema attributes (e.g. `"role": "admin"`, `"is_verified": 1`), silently elevating their permissions without administrative intervention.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### 1. IDOR Proof of Concept
```http
GET /api/user/profile?user_id=1 HTTP/1.1
Host: 127.0.0.1:8000
Cookie: session_token=<bob_contractor_jwt>
```
**Response:** Leaks Administrator record and private token:
```json
{
    "id": 1,
    "username": "admin",
    "role": "admin",
    "email": "security-admin@swynex.local",
    "api_token": "swynex_live_admin_tok_99182a8b"
}
```

### 2. Mass Assignment Proof of Concept
```http
PUT /api/user/profile HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json
Cookie: session_token=<bob_contractor_jwt>

{
    "role": "admin",
    "is_verified": 1
}
```
**Response:** Database updates `role` to `admin`.

---

## 💥 Impact Analysis
- **Horizontal Privilege Abuse:** Contractors access executive communications and private credentials.
- **Vertical Privilege Escalation:** Complete platform compromise via self-elevation to System Administrator.

---

## 🛡️ Remediation & Defensive Implementation

1. **Contextual Identity Gating:** Enforce caller identity verification. Standard users may only read/write their own records (`caller_id == target_id`); viewing other profiles requires administrative RBAC validation.
2. **Strict DTO Allowlisting:** Prohibit dynamic mapping of incoming request bodies. Restrict updates to an explicit whitelist of safe fields (`full_name`, `bio`), discarding privileged columns.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/database.py`)
```python
set_clauses = [f"{key} = ?" for key in fields.keys()]
cursor.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", list(fields.values()) + [user_id])
```

#### Remediated Code (`lab/secure_app/database.py`)
```python
ALLOWED_FIELDS = {"full_name", "bio"}

def update_user_profile_secure(user_id: int, fields: dict) -> Tuple[bool, str]:
    filtered = {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}
    if not filtered:
        return False, "No permitted fields provided."

    set_clauses = [f"{col} = ?" for col in filtered.keys()]
    values = list(filtered.values()) + [user_id]
    cursor.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", values)
    return True, "Profile updated successfully."
```

---

## ✅ Verification
Validated via automated test cases `test_08_mass_assignment_prevented_by_field_whitelist` and `test_13_bola_idor_access_control_logic` in `tests/test_web_security_controls.py`.

