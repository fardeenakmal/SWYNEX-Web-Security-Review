"""SWYNEX Automated Web Security Auditor & Compliance Inspector.

Defensive Auditing Tool for Web Applications:
- Evaluates HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.).
- Inspects Session Cookie Flags (HttpOnly, Secure, SameSite).
- Evaluates CORS Configuration & Insecure Origin Reflection.
- Inspects Server Banner Information Disclosure & Traceback Leakage.
- Generates CVSS-referenced compliance scores, grades (A+ to F), and remediation guidance.

Zero External Dependencies: Built with Python 3.8+ standard library.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

EXPECTED_SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "weight": 25,
        "description": "Restricts resource loading and execution to prevent Cross-Site Scripting (XSS).",
        "recommended": "default-src 'self'; script-src 'self'; frame-ancestors 'none';",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "weight": 15,
        "description": "Protects users against Clickjacking attacks by restricting framing.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "weight": 15,
        "description": "Prevents MIME-type sniffing by browsers.",
        "recommended": "nosniff",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "weight": 20,
        "description": "Enforces HTTPS connections and guards against SSL stripping.",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "weight": 10,
        "description": "Governs how much referrer information should be included with requests.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "weight": 15,
        "description": "Controls browser features (camera, microphone, geolocation).",
        "recommended": "geolocation=(), camera=(), microphone=()",
    },
}


class WebSecurityAuditor:
    """Performs defensive analysis of a target web service."""

    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.results: Dict[str, Any] = {
            "target": self.target_url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "score": 100,
            "grade": "A+",
            "header_checks": {},
            "cookie_checks": [],
            "cors_checks": {},
            "info_disclosure_checks": {},
            "findings": [],
            "remediation_summary": [],
        }

    def _make_request(
        self,
        endpoint: str = "/",
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> Tuple[int, Dict[str, str], bytes, List[str]]:
        url = f"{self.target_url}{endpoint}"
        req_headers = {"User-Agent": "SWYNEX-SecurityAuditor/2.0"}
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                resp_headers = {k.title(): v for k, v in response.headers.items()}
                raw_cookies = response.headers.get_all("Set-Cookie") or []
                body = response.read()
                return status, resp_headers, body, raw_cookies
        except urllib.error.HTTPError as e:
            resp_headers = {k.title(): v for k, v in e.headers.items()}
            raw_cookies = e.headers.get_all("Set-Cookie") or []
            body = e.read()
            return e.code, resp_headers, body, raw_cookies
        except Exception as e:
            return 0, {}, str(e).encode("utf-8"), []

    def audit_security_headers(self, headers: Dict[str, str]) -> None:
        """Evaluates presence and configuration of defense-in-depth security headers."""
        score_deductions = 0
        canonical_headers = {k.lower(): (k, v) for k, v in headers.items()}

        for header_name, meta in EXPECTED_SECURITY_HEADERS.items():
            lower_name = header_name.lower()
            if lower_name in canonical_headers:
                actual_name, actual_value = canonical_headers[lower_name]
                self.results["header_checks"][header_name] = {
                    "present": True,
                    "value": actual_value,
                    "status": "PASS",
                }
            else:
                score_deductions += meta["weight"]
                self.results["header_checks"][header_name] = {
                    "present": False,
                    "severity": meta["severity"],
                    "status": "FAIL",
                    "description": meta["description"],
                    "recommended": meta["recommended"],
                }
                self.results["findings"].append(
                    {
                        "id": f"HDR-MISSING-{header_name.upper().replace('-', '_')}",
                        "title": f"Missing Security Header: {header_name}",
                        "severity": meta["severity"],
                        "description": meta["description"],
                        "remediation": f"Configure web server to return '{header_name}: {meta['recommended']}'",
                    }
                )

        self.results["score"] = max(0, self.results["score"] - score_deductions)

    def audit_cookies(self, raw_cookies: List[str]) -> None:
        """Inspects Set-Cookie directives for HttpOnly, Secure, and SameSite flags."""
        if not raw_cookies:
            # Try fetching /login or dashboard to inspect cookies
            _, _, _, raw_cookies = self._make_request("/login")

        for cookie_str in raw_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            cookie_name = parts[0].split("=")[0] if "=" in parts[0] else "Unknown"

            flags = {p.lower(): p for p in parts[1:]}
            has_httponly = any("httponly" in f for f in flags)
            has_secure = any("secure" in f for f in flags)
            has_samesite = any("samesite" in f for f in flags)

            cookie_report = {
                "name": cookie_name,
                "httponly": has_httponly,
                "secure": has_secure,
                "samesite": has_samesite,
            }
            self.results["cookie_checks"].append(cookie_report)

            if not has_httponly:
                self.results["score"] = max(0, self.results["score"] - 10)
                self.results["findings"].append(
                    {
                        "id": f"CK-NO-HTTPONLY-{cookie_name}",
                        "title": f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        "severity": "HIGH",
                        "description": "Cookie is accessible via client-side JavaScript (document.cookie), enabling session theft via XSS.",
                        "remediation": "Append 'HttpOnly' flag to Set-Cookie header.",
                    }
                )

            if not has_samesite:
                self.results["score"] = max(0, self.results["score"] - 5)
                self.results["findings"].append(
                    {
                        "id": f"CK-NO-SAMESITE-{cookie_name}",
                        "title": f"Cookie Missing SameSite Flag: {cookie_name}",
                        "severity": "MEDIUM",
                        "description": "Cookie without SameSite may be sent in cross-site contexts, increasing CSRF susceptibility.",
                        "remediation": "Append 'SameSite=Strict' or 'SameSite=Lax' to Set-Cookie header.",
                    }
                )

    def audit_cors_configuration(self) -> None:
        """Tests CORS policy for unsafe wildcard origin reflection with credentials."""
        test_origin = "https://unauthorized-attacker-site.com"
        status, headers, _, _ = self._make_request(
            "/",
            headers={"Origin": test_origin},
            method="OPTIONS",
        )

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        is_insecure = False
        details = []

        if acao == "*":
            details.append("Wildcard origin '*' permitted.")
            if acac.lower() == "true":
                is_insecure = True
                details.append("Wildcard origin combined with Allow-Credentials: true!")
        elif acao == test_origin:
            is_insecure = True
            details.append(f"Server dynamically reflected untrusted origin: {test_origin}")
            if acac.lower() == "true":
                details.append("Untrusted origin allowed to send user session credentials!")

        self.results["cors_checks"] = {
            "origin_tested": test_origin,
            "allow_origin": acao,
            "allow_credentials": acac,
            "status": "FAIL" if is_insecure else "PASS",
            "details": details,
        }

        if is_insecure:
            self.results["score"] = max(0, self.results["score"] - 15)
            self.results["findings"].append(
                {
                    "id": "CORS-INSECURE-CONFIGURATION",
                    "title": "Insecure Cross-Origin Resource Sharing (CORS) Policy",
                    "severity": "HIGH",
                    "description": "Server permits unvetted origins or echoes arbitrary origins with credential support.",
                    "remediation": "Enforce a strict whitelist of authorized origins and avoid reflection.",
                }
            )

    def audit_information_disclosure(self, headers: Dict[str, str]) -> None:
        """Inspects server banners and error handling for verbose leaks."""
        server_banner = headers.get("Server", "")
        has_verbose_banner = False
        if server_banner and ("/" in server_banner or "vulnerable" in server_banner.lower()):
            has_verbose_banner = True
            self.results["score"] = max(0, self.results["score"] - 5)
            self.results["findings"].append(
                {
                    "id": "INFO-SERVER-BANNER-DISCLOSURE",
                    "title": "Verbose Server Banner Information Disclosure",
                    "severity": "LOW",
                    "description": f"Server exposes detailed implementation information: '{server_banner}'",
                    "remediation": "Suppress or genericize the 'Server' response header.",
                }
            )

        # Test error disclosure
        status, _, err_body, _ = self._make_request("/api/user/profile?user_id=invalid_text_str")
        err_text = err_body.decode("utf-8", errors="replace")
        has_traceback_leak = (
            "Traceback (most recent call last)" in err_text
            or "500 INTERNAL SERVER ERROR" in err_text
            or "Exception:" in err_text
        )

        if has_traceback_leak:
            self.results["score"] = max(0, self.results["score"] - 15)
            self.results["findings"].append(
                {
                    "id": "INFO-STACK-TRACE-DISCLOSURE",
                    "title": "Verbose Exception Stack Trace Disclosure",
                    "severity": "MEDIUM",
                    "description": "Server leaks internal Python stack traces, file paths, and environment details on error.",
                    "remediation": "Implement custom generic error handlers and route stack traces to secure backend logs.",
                }
            )

        self.results["info_disclosure_checks"] = {
            "server_banner": server_banner,
            "banner_disclosed": has_verbose_banner,
            "stack_trace_leaked": has_traceback_leak,
        }

    def _calculate_grade(self) -> str:
        score = self.results["score"]
        if score >= 90:
            return "A+" if score >= 95 else "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def run_full_audit(self) -> Dict[str, Any]:
        """Runs complete defensive audit against the target service."""
        status, headers, body, cookies = self._make_request("/")
        if status == 0:
            self.results["score"] = 0
            self.results["grade"] = "F"
            self.results["error"] = f"Failed to connect to target: {body.decode('utf-8', errors='replace')}"
            return self.results

        self.audit_security_headers(headers)
        self.audit_cookies(cookies)
        self.audit_cors_configuration()
        self.audit_information_disclosure(headers)

        self.results["grade"] = self._calculate_grade()
        return self.results

    def generate_terminal_report(self) -> str:
        """Renders an ASCII compliance report."""
        res = self.results
        lines = []
        lines.append("=" * 72)
        lines.append(f"  SWYNEX Automated Web Security Audit Report")
        lines.append(f"  Target: {res['target']} | Date: {res['timestamp']}")
        lines.append("=" * 72)
        lines.append(f"  Security Score: {res['score']}/100  |  Compliance Grade: [{res['grade']}]")
        lines.append("-" * 72)

        lines.append("\n[+] HTTP SECURITY HEADERS:")
        for h, data in res["header_checks"].items():
            status_symbol = "[✓ PASS]" if data["status"] == "PASS" else "[✗ FAIL]"
            val_str = f" : {data['value'][:40]}..." if data.get("value") else ""
            lines.append(f"  {status_symbol} {h:<28}{val_str}")

        lines.append("\n[+] CORS CONFIGURATION:")
        cors = res["cors_checks"]
        cors_sym = "[✓ PASS]" if cors.get("status") == "PASS" else "[✗ FAIL]"
        lines.append(f"  {cors_sym} Allow-Origin: '{cors.get('allow_origin', '')}'")
        for d in cors.get("details", []):
            lines.append(f"      • {d}")

        lines.append("\n[+] INFORMATION DISCLOSURE CHECKS:")
        info = res["info_disclosure_checks"]
        banner_sym = "[✗ WARN]" if info.get("banner_disclosed") else "[✓ PASS]"
        stack_sym = "[✗ FAIL]" if info.get("stack_trace_leaked") else "[✓ PASS]"
        lines.append(f"  {banner_sym} Server Banner: '{info.get('server_banner', '')}'")
        lines.append(f"  {stack_sym} Stack Trace Leakage: {'Detected' if info.get('stack_trace_leaked') else 'None'}")

        lines.append("\n[+] IDENTIFIED DEFENSIVE FINDINGS & REMEDIATIONS:")
        if not res["findings"]:
            lines.append("  [✓] Zero compliance violations detected! Target meets security baseline.")
        else:
            for idx, f in enumerate(res["findings"], 1):
                lines.append(f"  {idx}. [{f['severity']}] {f['title']}")
                lines.append(f"     Remediation: {f['remediation']}")

        lines.append("=" * 72)
        return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="SWYNEX Automated Web Security Auditor")
    parser.add_argument("--target", default="http://127.0.0.1:8000", help="Target URL to audit")
    parser.add_argument("--output", default="auditor_results.json", help="Path to save JSON findings")
    parser.add_argument("--verbose", action="store_true", help="Print verbose JSON output")
    args = parser.parse_args()

    auditor = WebSecurityAuditor(args.target)
    results = auditor.run_full_audit()
    print(auditor.generate_terminal_report())

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Structured audit findings exported to: {args.output}")


if __name__ == "__main__":
    main()

