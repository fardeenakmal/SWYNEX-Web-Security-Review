# Security Finding Dossier: SEC-WEB-001

## 📌 Vulnerability Identification
- **Finding ID:** `SEC-WEB-001`
- **Title:** OS Command Injection (Remote Code Execution)
- **Vulnerability Category:** OWASP Top 10:2021 – A03: Injection
- **CWE Identifier:** CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CVSS v3.1 Base Score:** **9.8 (Critical)**
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected Component:** `lab/vulnerable_app/server.py` (`POST /api/tools/ping`)
- **Assessor:** Fardeen Akmal (`fardeenakmal123@gmail.com`)
- **Remediation Status:** **REMEDIATED**

---

## 🔬 Technical Description & Vulnerability Mechanics
The application exposes a diagnostic network connectivity utility at `/api/tools/ping`. The backend implementation constructs a system command string using string interpolation and passes it directly to `subprocess.Popen(command, shell=True)`.

Because the execution flag `shell=True` is enabled, the string is evaluated by the system command shell (`/bin/sh` on Unix or `cmd.exe` on Windows). An attacker can supply shell metacharacters (such as `;`, `&&`, `|`, `$(...)`, or backticks) within the `target` parameter to execute arbitrary operating system commands with the privileges of the web application service account.

---

## 🧪 Controlled Lab Proof of Concept (Defensive Observation)

### Vulnerable Request
```http
POST /api/tools/ping HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json

{
    "target": "127.0.0.1; whoami; id"
}
```

### Vulnerable Server Response
```json
{
    "command_executed": "ping -c 1 127.0.0.1; whoami; id",
    "exit_code": 0,
    "stdout": "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms\n\nfardeenakmal\nuid=1000(fardeenakmal) gid=1000(fardeenakmal) groups=1000(fardeenakmal)\n",
    "stderr": ""
}
```

---

## 💥 Impact Analysis
- **Confidentiality:** Total. Full read access to all local files, database passwords, environment variables, and source code.
- **Integrity:** Total. Arbitrary file modification, database alteration, and rogue script injection.
- **Availability:** Total. Attackers can terminate host processes or destroy system services.

---

## 🛡️ Remediation & Defensive Implementation

1. **Input Validation:** Enforce strict RFC 1123 hostname and IP address regex validation.
2. **Subprocess Isolation:** Eliminate `shell=True`. Pass arguments as an array of discrete parameters (`["ping", "-c", "1", validated_host]`), disarming shell interpretation.

### Code Comparison

#### Vulnerable Code (`lab/vulnerable_app/server.py`)
```python
command = f"ping -c 1 {target}"
proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
```

#### Remediated Code (`lab/secure_app/security_controls.py`)
```python
HOSTNAME_REGEX = re.compile(r"^(?:(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

def safe_network_ping(target: str) -> dict:
    if not HOSTNAME_REGEX.match(target.strip()):
        raise SecurityException("Invalid hostname format.")
    cmd_args = ["ping", "-c", "1", "-W", "3", target.strip()]
    proc = subprocess.run(cmd_args, shell=False, capture_output=True, timeout=4)
    return {"status": "success", "stdout": proc.stdout}
```

---

## ✅ Verification
Validated via automated test case `test_02_command_injection_mitigated_in_secure_app` in `tests/test_web_security_controls.py`.

