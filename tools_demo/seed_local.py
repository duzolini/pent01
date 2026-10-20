"""Seed a scan with findings that point at the local vuln_app, so we can run
the real validators against it. No network beyond localhost."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import store
from orchestrator.models import ScanResult, Finding, Severity


def _weak_jwt(secret: str) -> str:
    import base64, hashlib, hmac, json
    def b(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    h = b(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b(json.dumps({"user": "admin"}).encode())
    mac = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b(mac)}"


B = "http://127.0.0.1:5001"
r = ScanResult(scope_name="local-vuln-lab", status="done",
               targets=["127.0.0.1"],
               authorization={"client": "self", "authorized_by": "operator",
                              "authorization_ref": "local lab", "authorized": True})

F = [
    Finding("Reflected XSS candidate", Severity.HIGH, f"{B}/search?q=test", "nuclei",
            "Parameter 'q' appears to reflect input.", metadata={"param": "q"}),
    Finding("SQL injection candidate", Severity.CRITICAL, f"{B}/item?id=1", "nuclei",
            "Parameter 'id' appears injectable.", metadata={"param": "id"}),
    Finding("Local file inclusion candidate", Severity.HIGH, f"{B}/download?file=readme.txt",
            "nuclei", "Parameter 'file' may allow path traversal.", metadata={"param": "file"}),
    Finding("Open redirect candidate", Severity.MEDIUM, f"{B}/go?next=/home", "nuclei",
            "Parameter 'next' may be an open redirect.", metadata={"param": "next"}),
    Finding("Exposed .git directory", Severity.CRITICAL, f"{B}/", "nuclei",
            "A .git directory may be exposed."),
    Finding("Directory listing enabled", Severity.LOW, f"{B}/assets/", "nikto",
            "Directory indexing may be enabled."),
    Finding("Missing security header: content-security-policy", Severity.LOW, f"{B}/",
            "http-headers", "CSP may be missing."),
    Finding("Apache Struts RCE (CVE-2017-5638)", Severity.HIGH, f"{B}/upload", "nuclei",
            "Responds like CVE-2017-5638.", metadata={"template": "CVE-2017-5638"}),
    Finding("SSH default credentials", Severity.HIGH, "127.0.0.1:22", "nuclei",
            "SSH login present; test for weak credentials."),
    Finding("CORS misconfiguration", Severity.MEDIUM, f"{B}/api", "nuclei",
            "Access-Control-Allow-Origin may reflect arbitrary origins."),
    Finding("SSRF candidate", Severity.HIGH, f"{B}/fetch?url=http://x", "nuclei",
            "Parameter 'url' may allow server-side requests.",
            metadata={"param": "url", "oob_url": f"{B}/ssrf-canary"}),
    Finding("JWT weak secret", Severity.HIGH, f"{B}/", "nuclei",
            "A JWT appears signed with a weak HMAC secret.",
            metadata={"token": _weak_jwt("secret")}),
    Finding("Broken access control — admin panel", Severity.HIGH, f"{B}/admin", "nuclei",
            "Admin page may be reachable without authentication."),
    Finding("OS command injection", Severity.CRITICAL, f"{B}/ping?host=127.0.0.1", "nuclei",
            "Parameter 'host' may flow into a shell command.", metadata={"param": "host"}),
]
for f in F:
    r.add_finding(f)
store.save(r)
print(r.scan_id)
