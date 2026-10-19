"""Seed a scan with findings that point at the local vuln_app, so we can run
the real validators against it. No network beyond localhost."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import store
from orchestrator.models import ScanResult, Finding, Severity

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
]
for f in F:
    r.add_finding(f)
store.save(r)
print(r.scan_id)
