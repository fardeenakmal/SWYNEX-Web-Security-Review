# Security Finding Dossier: SEC-WEB-002

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-002`
- **Title:** Server-Side Request Forgery (SSRF)
- **Vulnerability Category:** OWASP Top 10:2021 – A10: Server-Side Request Forgery (SSRF)
- **CWE Identifier:** CWE-918: Server-Side Request Forgery (SSRF)
- **CVSS v3.1 Base Score:** **8.6 (Critical)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
- **Affected Component:** `lab/vulnerable_app/server.py` (`POST /api/tools/fetch-url`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The application incorporates a webhook and external URL fetcher at `/api/tools/fetch-url`. The service accepts a client-provided `url` parameter and executes an HTTP request via Python's standard `urllib.request.urlopen`.

The endpoint lacked protocol whitelisting and destination IP validation. Consequently, authenticated users can force the server to initiate requests against local loopback interfaces (`127.0.0.1`, `localhost`), internal private subnets (`10.0.0.0/8`, `192.168.0.0/16`), and cloud infrastructure metadata services (`169.254.169.254`), bypassing perimeter firewalls.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Vulnerable Request
```http
POST /api/tools/fetch-url HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json

{
    "url": "http://127.0.0.1:8000/api/documents"
}
```

### Vulnerable Server Response
```json
{
    "target_url": "http://127.0.0.1:8000/api/documents",
    "status_code": 200,
    "body_preview": "{\"documents\": [{\"id\": 1, \"title\": \"Corporate Infrastructure Overview\"...}]}"
}
```

---

## 💥 Impact Analysis
- **Internal Reconnaissance:** Port scanning and identification of unauthenticated internal services (Redis, Elasticsearch, Consul).
- **Cloud Metadata Harvesting:** On cloud environments (AWS, GCP, Azure), querying `169.254.169.254` extracts temporary IAM access keys and instance credentials.
- **Protocol Smuggling:** Attacker can abuse schemes like `gopher://` or `file:///` to access internal services.

---

## 🛡️ Remediation & Defensive Implementation

1. **Protocol Scheme Restriction:** Permit only `http` and `https`.
2. **DNS Pre-Resolution & IP Filtering:** Resolve the target hostname prior to opening connections and cross-reference all resolved IP addresses against loopback, private RFC 1918 subnets, and cloud metadata ranges.
3. **Redirect Suppression:** Prevent HTTP redirect chaining into private subnets.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
req = urllib.request.Request(target_url)
with urllib.request.urlopen(req) as resp:
    body = resp.read()
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
def validate_ssrf_safe_url(url_str: str) -> Tuple[str, str, int]:
    parsed = urllib.parse.urlparse(url_str)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SecurityException("Only HTTP and HTTPS permitted.")

    addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or 80)
    for item in addr_info:
        ip = ipaddress.ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise SecurityException(f"Destination IP {ip} is prohibited.")
    return parsed.scheme.lower(), parsed.hostname, parsed.port or 80
```

---

## ✅ Verification
Validated via automated test case `test_03_ssrf_mitigated_blocking_internal_loopback_and_metadata` in `tests/test_web_security_controls.py`.

