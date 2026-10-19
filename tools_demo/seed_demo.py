"""Seed a realistic demo scan so the report and dashboard have content to show.

This writes synthetic data only — it performs no network activity. For the demo
scope we use example.com (IANA-reserved) with authorized: true.
"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import store
from orchestrator.models import ScanResult, Asset, Finding, Severity, StageResult

r = ScanResult(scope_name="acme-corp-external", status="done")
r.created_at = time.time() - 142
r.finished_at = time.time()
r.targets = ["acme-corp.example.com"]
r.authorization = {
    "client": "ACME Corp", "authorized_by": "J. Silva (CISO)",
    "authorization_ref": "SOW-2026-014", "expires": "2026-12-31", "authorized": True,
}

# --- assets ---
subs = ["www.acme-corp.example.com", "api.acme-corp.example.com",
        "staging.acme-corp.example.com", "vpn.acme-corp.example.com",
        "mail.acme-corp.example.com"]
for s in subs:
    r.add_asset(Asset("subdomain", s, source="subfinder"))
for h, ip in [("www.acme-corp.example.com", "203.0.113.10"),
              ("api.acme-corp.example.com", "203.0.113.11")]:
    r.add_asset(Asset("host", h, source="dnsx", metadata={"a": [ip]}))
for svc, port, prod in [("203.0.113.10", 443, "nginx 1.18.0"),
                        ("203.0.113.10", 80, "nginx 1.18.0"),
                        ("203.0.113.11", 443, "nginx 1.18.0"),
                        ("203.0.113.11", 22, "OpenSSH 8.2p1")]:
    r.add_asset(Asset("service", f"{svc}:{port}", source="nmap",
                      metadata={"host": svc, "port": port, "service": "http", "product": prod}))
for url, code, title in [("https://www.acme-corp.example.com", 200, "ACME Corp — Home"),
                         ("https://api.acme-corp.example.com", 403, "Forbidden"),
                         ("https://staging.acme-corp.example.com", 200, "ACME Staging (basic auth)")]:
    r.add_asset(Asset("url", url, source="httpx",
                      metadata={"status_code": code, "title": title,
                                "webserver": "nginx", "tech": ["nginx", "jQuery"]}))

# --- findings ---
F = [
    Finding("Exposed .git directory", Severity.CRITICAL,
            "https://staging.acme-corp.example.com/.git/", "nuclei",
            "The .git directory is publicly accessible, exposing full source history.",
            evidence="https://staging.acme-corp.example.com/.git/HEAD",
            reference="https://owasp.org/www-community/attacks/Source_code_disclosure"),
    Finding("Deprecated TLS version supported: TLSv1.1", Severity.HIGH,
            "staging.acme-corp.example.com:443", "tls-check",
            "Server negotiated TLSv1.1, which is deprecated and must be disabled."),
    Finding("Apache Struts RCE (CVE-2017-5638) — candidate", Severity.HIGH,
            "https://api.acme-corp.example.com/upload", "nuclei",
            "Endpoint responds to a crafted Content-Type consistent with CVE-2017-5638.",
            reference="https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
            metadata={"template": "CVE-2017-5638"}),
    Finding("Missing security header: strict-transport-security", Severity.MEDIUM,
            "https://www.acme-corp.example.com", "http-headers",
            "Response does not set 'strict-transport-security'.",
            reference="https://owasp.org/www-project-secure-headers/"),
    Finding("TLS certificate expires in 12 days", Severity.MEDIUM,
            "www.acme-corp.example.com:443", "tls-check",
            "Certificate expires soon.", evidence="notAfter=Oct 31 23:59:59 2026 GMT"),
    Finding("Server version disclosed", Severity.LOW,
            "https://www.acme-corp.example.com", "http-headers",
            "Server header reveals software/version: nginx/1.18.0", evidence="nginx/1.18.0"),
    Finding("Missing security header: content-security-policy", Severity.LOW,
            "https://www.acme-corp.example.com", "http-headers",
            "Response does not set 'content-security-policy'."),
    Finding("Directory listing enabled", Severity.LOW,
            "https://staging.acme-corp.example.com/assets/", "nikto",
            "Directory indexing is enabled under /assets/.", metadata={"id": "001"}),
    Finding("robots.txt reveals internal paths", Severity.INFO,
            "https://www.acme-corp.example.com/robots.txt", "nuclei",
            "robots.txt discloses /admin and /internal paths."),
]
for f in F:
    r.add_finding(f)

# --- stage log ---
for stage, tool, status, note in [
    ("recon", "subfinder", "ok", ""), ("recon", "dnsx", "ok", ""),
    ("recon", "httpx", "ok", ""), ("ports", "naabu", "ok", ""),
    ("ports", "nmap", "ok", ""), ("web", "nuclei", "ok", ""),
    ("web", "nikto", "ok", ""), ("web", "http-headers", "ok", ""),
    ("web", "tls-check", "ok", ""),
]:
    sr = StageResult(stage=stage, tool=tool, status=status, skipped_reason=note,
                     started_at=r.created_at, finished_at=r.finished_at)
    r.stages.append(sr)

path = store.save(r)
print(f"seeded scan {r.scan_id} -> {path}")
print(r.scan_id)
