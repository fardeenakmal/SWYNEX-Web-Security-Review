# Security Finding Dossier: SEC-WEB-004

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-004`
- **Title:** Path Traversal & Arbitrary File Disclosure
- **Vulnerability Category:** OWASP Top 10:2021 – A01: Broken Access Control
- **CWE Identifier:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CVSS v3.1 Base Score:** **7.5 (High)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (`GET /api/documents/download?file=...`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The document management service exposes an export endpoint at `GET /api/documents/download?file=...`. The backend combines the client-supplied `file` parameter with the base directory using `os.path.join(DOCS_DIR, filename)`.

In Python, `os.path.join` does not sanitize dot-dot-slash (`../`) directory navigation sequences. An attacker supplying relative traversal paths (e.g. `../../../../etc/passwd` or `../../vulnerable_portal.db`) escapes the document directory sandbox, allowing unauthorized inspection of arbitrary operating system files, database schemas, and application source code.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Vulnerable Request
```http
GET /api/documents/download?file=../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1:8000
```

### Vulnerable Server Response
```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
fardeenakmal:x:1000:1000:Fardeen Akmal:/home/fardeenakmal:/bin/bash
```

---

## 💥 Impact Analysis
- **Source Code & Credentials Exposure:** Extraction of application logic, hardcoded secrets, and local databases.
- **System Enumeration:** Reading `/etc/passwd`, `/proc/version`, and network configs to facilitate privilege escalation.

---

## 🛡️ Remediation & Defensive Implementation

1. **Input Rejection:** Reject filenames containing null bytes (`\0`) or path separators (`/`, `\`, `..`).
2. **Path Canonicalization:** Resolve real absolute paths via `os.path.realpath`.
3. **Boundary Verification:** Verify that `os.path.commonpath([base_dir, target_path]) == base_dir` and `target_path.startswith(base_dir + os.sep)`.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
target_path = os.path.join(DOCS_DIR, filename)
with open(target_path, "rb") as f:
    content = f.read()
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
def resolve_safe_file_path(base_dir: str, requested_filename: str) -> str:
    if "\0" in requested_filename:
        raise SecurityException("Null byte detected.")
    if ".." in requested_filename or "/" in requested_filename or "\\" in requested_filename:
        raise SecurityException("Directory traversal sequence detected.")

    canonical_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(canonical_base, requested_filename.strip()))

    if not target_path.startswith(canonical_base + os.sep):
        raise SecurityException("Directory traversal attempt detected.")
    return target_path
```

---

## ✅ Verification
Validated via automated test case `test_06_path_traversal_mitigated_by_canonical_boundary_check` in `tests/test_web_security_controls.py`.

