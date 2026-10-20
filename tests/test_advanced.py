"""Tests for the new validators, authenticated scanning, and exporters."""

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools_demo"))

from werkzeug.serving import make_server  # noqa: E402

from orchestrator import export, validators  # noqa: E402
from orchestrator.models import Finding, ScanResult, Severity  # noqa: E402
from orchestrator.scope import Scope  # noqa: E402

PORT = 5095
B = f"http://127.0.0.1:{PORT}"


class _Server:
    def __enter__(self):
        from vuln_app import app
        self.srv = make_server("127.0.0.1", PORT, app, threaded=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.4)
        return self

    def __exit__(self, *a):
        self.srv.shutdown()


def _scope(**kw):
    return Scope(name="lab", authorized=True, hosts=["127.0.0.1"], **kw)


def test_new_validators_confirm():
    with _Server():
        r = ScanResult()
        r.add_finding(Finding("SSTI candidate", Severity.CRITICAL, f"{B}/greet?name=x",
                              "x", metadata={"param": "name"}))
        r.add_finding(Finding("XXE candidate", Severity.HIGH, f"{B}/xml", "x"))
        r.add_finding(Finding("GraphQL introspection", Severity.MEDIUM, f"{B}/graphql", "x"))
        r.add_finding(Finding("NoSQL injection", Severity.HIGH, f"{B}/login-nosql?username=admin",
                              "x", metadata={"param": "username"}))
        r.add_finding(Finding("Subdomain takeover", Severity.HIGH, f"{B}/takeover", "x"))
        validators.validate_findings(r, _scope())
    by = {f.title: f.validation for f in r.findings}
    assert by["SSTI candidate"].status == "confirmed" and "1787569" in by["SSTI candidate"].evidence
    assert by["XXE candidate"].status == "confirmed" and "root:x:0:0" in by["XXE candidate"].evidence
    assert by["GraphQL introspection"].status == "confirmed"
    assert by["NoSQL injection"].status == "confirmed"
    assert by["Subdomain takeover"].status == "confirmed"


def test_authenticated_scanning():
    with _Server():
        # Unauthenticated: /secret returns 401 -> not confirmed.
        r = ScanResult()
        r.add_finding(Finding("Broken access control — secret", Severity.HIGH, f"{B}/secret", "x"))
        validators.validate_findings(r, _scope())
        assert r.findings[0].validation.status == "not_confirmed"

        # Bearer token -> /secret returns 200 -> confirmed.
        r2 = ScanResult()
        r2.add_finding(Finding("Broken access control — secret", Severity.HIGH, f"{B}/secret", "x"))
        validators.validate_findings(r2, _scope(auth={"type": "bearer", "token": "testtoken"}))
        assert r2.findings[0].validation.status == "confirmed"

        # Form login -> session cookie -> /secret 200 -> confirmed.
        r3 = ScanResult()
        r3.add_finding(Finding("Broken access control — secret", Severity.HIGH, f"{B}/secret", "x"))
        validators.validate_findings(r3, _scope(auth={
            "type": "form", "login_url": f"{B}/login",
            "data": {"user": "admin", "pass": "admin"}, "success": "Welcome"}))
        assert r3.findings[0].validation.status == "confirmed"


def _sample():
    r = ScanResult(scope_name="s")
    r.add_finding(Finding("SQL injection", Severity.CRITICAL, "http://h/item?id=1", "nuclei",
                          "injectable", metadata={"owasp": "A03", "param": "id"}))
    r.add_finding(Finding("Missing CSP", Severity.LOW, "http://h/", "http-headers"))
    return r


def test_exports():
    r = _sample()
    # SARIF
    sarif = json.loads(export.to_sarif(r))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert any(rule["id"] == "A03" for rule in sarif["runs"][0]["tool"]["driver"]["rules"])
    # findings JSON
    data = json.loads(export.to_findings_json(r))
    assert data["findings"][0]["cvss"] == 9.5
    assert "curl" in data["findings"][0]["poc"]
    # CSV
    csv_text = export.to_csv(r)
    assert "severity,cvss,owasp" in csv_text and "SQL injection" in csv_text
    # DefectDojo
    dd = json.loads(export.to_defectdojo(r))
    assert dd["findings"][0]["severity"] == "Critical"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
