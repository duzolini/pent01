"""Tests for OWASP Top 10 categorisation and the access-control / command-
injection validators."""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools_demo"))

from werkzeug.serving import make_server  # noqa: E402

import orchestrator.oob as oob  # noqa: E402
from orchestrator import owasp, validators  # noqa: E402
from orchestrator.models import Finding, ScanResult, Severity  # noqa: E402
from orchestrator.scope import Scope  # noqa: E402

APP_PORT = 5096
OOB_PORT = 8096


def test_categorize_and_coverage():
    r = ScanResult()
    r.add_finding(Finding("SQL injection candidate", Severity.CRITICAL, "http://h/a", "x"))
    r.add_finding(Finding("SSRF candidate", Severity.HIGH, "http://h/b", "x"))
    r.add_finding(Finding("Missing security header: content-security-policy",
                          Severity.LOW, "http://h/", "x"))
    r.add_finding(Finding("TLS certificate expiry", Severity.MEDIUM, "h:443", "x"))
    r.add_finding(Finding("SSH default credentials", Severity.HIGH, "h:22", "x"))
    assert owasp.categorize(r.findings[0]) == "A03"
    assert owasp.categorize(r.findings[1]) == "A10"
    assert owasp.categorize(r.findings[2]) == "A05"
    assert owasp.categorize(r.findings[3]) == "A02"
    assert owasp.categorize(r.findings[4]) == "A07"
    cov = {row["id"]: row for row in owasp.coverage(r)}
    assert len(cov) == 10
    assert cov["A03"]["count"] == 1 and cov["A10"]["count"] == 1
    assert cov["A04"]["count"] == 0  # insecure design — nothing auto-detected


def test_access_control_and_command_injection():
    oob.DEFAULT_LOG = Path("/tmp/owasp_oob.jsonl")
    if oob.DEFAULT_LOG.exists():
        oob.DEFAULT_LOG.unlink()
    from vuln_app import app
    srv = make_server("127.0.0.1", APP_PORT, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    listener = oob.OobListener("127.0.0.1", OOB_PORT)
    threading.Thread(target=listener.serve_forever, daemon=True).start()
    time.sleep(0.4)
    try:
        scope = Scope(name="lab", authorized=True, hosts=["127.0.0.1"],
                      intrusive=True, oob_url=f"http://127.0.0.1:{OOB_PORT}")
        r = ScanResult()
        r.add_finding(Finding("Broken access control — admin panel", Severity.HIGH,
                              f"http://127.0.0.1:{APP_PORT}/admin", "x"))
        r.add_finding(Finding("OS command injection", Severity.CRITICAL,
                              f"http://127.0.0.1:{APP_PORT}/ping?host=127.0.0.1", "x",
                              metadata={"param": "host"}))
        validators.validate_findings(r, scope)
        by = {f.title: f for f in r.findings}
        ac = by["Broken access control — admin panel"]
        ci = by["OS command injection"]
        assert ac.validation.status == "confirmed", ac.validation.detail
        assert ac.metadata.get("owasp") == "A01"
        assert ci.validation.status == "confirmed", ci.validation.detail
        assert ci.metadata.get("owasp") == "A03"
    finally:
        listener.shutdown()
        srv.shutdown()


def test_command_injection_requires_intrusive():
    scope = Scope(name="lab", authorized=True, hosts=["127.0.0.1"], intrusive=False)
    v = validators.CommandInjectionValidator()
    f = Finding("OS command injection", Severity.CRITICAL, "http://127.0.0.1/ping", "x")
    res = v.run(f, scope)
    assert res.status == "unverified" and "intrusive" in res.detail


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
