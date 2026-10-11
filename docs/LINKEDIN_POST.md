# LinkedIn Post Template: SWYNEX Web Security Review (Task 3)

```markdown
🛡️ Thrilled to present my latest cybersecurity project: SWYNEX Web Security Review!

As part of my internship at SWYNEX Technologies, I conducted an in-depth defensive web security review of an enterprise cloud management platform (SWYNEX CloudPortal) within an authorized educational laboratory environment.

🔍 Project Highlights & Deliverables:
• 8 Vulnerability Domains Audited: Command Injection (RCE), SSRF, Stored & Reflected XSS, Path Traversal, Unrestricted File Uploads, BOLA/IDOR, Mass Assignment, and Broken JWT Authentication.
• Dual Lab Architecture: Built an intentionally vulnerable testbed alongside a production-grade, hardened reference implementation (Python 3 stdlib, zero external dependencies).
• Defense-in-Depth Controls: Implemented strict RFC 1123 hostname regex validation, vectorized subprocess execution (shell=False), DNS pre-resolution SSRF filters (blocking loopback/private/metadata ranges), path canonicalization, DTO field allowlisting, and salted PBKDF2-HMAC-SHA256 password hashing.
• Automated Verification Suite: 15 comprehensive unit & integration tests achieving a 100% pass rate in under 5 seconds.
• Automated Compliance Tool: Developed a defensive security auditor evaluating HTTP security headers (CSP, HSTS, X-Frame-Options), cookie directives (HttpOnly, Secure, SameSite), and CORS policies.

📂 GitHub Repository: https://github.com/fardeenakmal/SWYNEX-Web-Security-Review

Special thanks to the SWYNEX Technologies team for the mentorship and challenging technical curriculum!

#Cybersecurity #WebSecurity #ApplicationSecurity #AppSec #OWASP #DevSecOps #Python #PenetrationTesting #InfoSec #SWYNEX
```
