# Security Finding Dossier: SEC-WEB-005

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-005`
- **Title:** Unrestricted / Insecure File Upload
- **Vulnerability Category:** OWASP Top 10:2021 – A04: Insecure Design
- **CWE Identifier:** CWE-434: Unrestricted Upload of File with Dangerous Type
- **CVSS v3.1 Base Score:** **7.8 (High)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (`POST /api/upload`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The application allows users to upload attachments and avatars at `POST /api/upload`. The vulnerable endpoint:
1. Blindly trusts client-supplied filenames (`form_filename`).
2. Fails to enforce an extension whitelist, permitting `.html`, `.svg`, `.py`, `.sh`, or web shell scripts.
3. Fails to inspect file content headers or MIME magic bytes.
4. Stores uploaded artifacts directly in a public, web-accessible folder (`uploads/`).

An attacker can upload malicious scripts or weaponized SVG/HTML files, resulting in persistent Cross-Site Scripting, server file manipulation, or Remote Code Execution when served by an interpreter.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Vulnerable Request
```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: multipart/form-data; boundary=---------------------------12345

-----------------------------12345
Content-Disposition: form-data; name="file"; filename="poc_exploit.html"
Content-Type: text/html

<script>alert(document.cookie)</script>
-----------------------------12345--
```

### Vulnerable Server Response
```json
{
    "status": "success",
    "filename": "poc_exploit.html",
    "saved_to": ".../lab/vulnerable_app/uploads/poc_exploit.html",
    "bytes_written": 40
}
```

---

## 💥 Impact Analysis
- **Stored Client-Side Attacks:** Serving malicious HTML/SVG directly from application domains compromises session cookies.
- **Web Shell Execution:** If served in an environment with script execution enabled (e.g. PHP, CGI, Node), weaponized uploads lead to complete server takeover.

---

## 🛡️ Remediation & Defensive Implementation

1. **Strict Extension Whitelist:** Restrict uploads strictly to safe image types (`.png`, `.jpg`, `.jpeg`).
2. **Magic Byte Signature Inspection:** Verify that binary magic headers match the declared image format.
3. **Randomized File Renaming:** Discard client-provided filenames and generate cryptographically random UUID4 identifiers (`uuid.uuid4().hex`).
4. **Isolated Storage:** Store uploads outside the web execution root.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
target_path = os.path.join(UPLOADS_DIR, client_filename)
with open(target_path, "wb") as f:
    f.write(file_data)
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

def validate_and_save_upload(client_filename: str, file_data: bytes, upload_directory: str):
    _, ext = os.path.splitext(client_filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise SecurityException("Extension not permitted.")

    if ext == ".png" and not file_data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SecurityException("MIME signature mismatch.")

    random_filename = f"{uuid.uuid4().hex}{ext}"
    safe_destination = resolve_safe_file_path(upload_directory, random_filename)
    with open(safe_destination, "wb") as f:
        f.write(file_data)
    return random_filename, safe_destination
```

---

## ✅ Verification
Validated via automated test case `test_07_file_upload_rejects_dangerous_extensions_and_fake_magic_bytes` in `tests/test_web_security_controls.py`.

