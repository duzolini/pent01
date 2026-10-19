"""End-to-end tests for the validation + exploit-planning layer.

Spins up the deliberately vulnerable demo app on localhost and asserts that the
safe validators actually confirm each class of finding with evidence. Also tests
the exploit planner's command generation and every execution gate — with no
external network and without running any exploit tool.
"""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools_demo"))

from werkzeug.serving import make_server  # noqa: E402

from orchestrator import exploit, validators  # noqa: E402
from orchestrator.models import Finding, Severity, ScanResult  # noqa: E402
from orchestrator.scope import Scope  # noqa: E402

PORT = 5099
B = f"http://127.0.0.1:{PORT}"


class _Server:
    def __init__(self):
        from vuln_app import app
        self.srv = make_server("127.0.0.1", PORT, app, threaded=True)
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.th.start()
        time.sleep(0.4)
        return self

    def __exit__(self, *a):
        self.srv.shutdown()


def _scope(intrusive=False):
    return Scope(name="lab", authorized=True, hosts=["127.0.0.1"], intrusive=intrusive)


def _result():
    r = ScanResult(scope_name="lab")
    r.add_finding(Finding("Reflected XSS candidate", Severity.HIGH, f"{B}/search?q=t",
                          "x", metadata={"param": "q"}))
    r.add_finding(Finding("SQL injection candidate", Severity.CRITICAL, f"{B}/item?id=1",
                          "x", metadata={"param": "id"}))
    r.add_finding(Finding("Local file inclusion", Severity.HIGH, f"{B}/download?file=x",
                          "x", metadata={"param": "file"}))
    r.add_finding(Finding("Open redirect", Severity.MEDIUM, f"{B}/go?next=/h",
                          "x", metadata={"param": "next"}))
    r.add_finding(Finding("Exposed .git directory", Severity.CRITICAL, f"{B}/", "x"))
    r.add_finding(Finding("Directory listing enabled", Severity.LOW, f"{B}/assets/", "x"))
    return r


def test_validators_confirm_real_vulns():
    with _Server():
        r = _result()
        confirmed = validators.validate_findings(r, _scope())
    by_title = {f.title: f.validation for f in r.findings}
    assert confirmed == 6, [f"{t}:{v.status}" for t, v in by_title.items()]
    assert by_title["SQL injection candidate"].status == "confirmed"
    assert "boolean diff" in by_title["SQL injection candidate"].evidence
    assert "root:x:0:0" in by_title["Local file inclusion"].evidence
    assert by_title["Reflected XSS candidate"].status == "confirmed"
    assert by_title["Exposed .git directory"].status == "confirmed"


def test_xss_not_confirmed_when_encoded():
    # A target that encodes output must NOT be reported as confirmed.
    v = validators.ReflectedXssValidator()
    f = Finding("Reflected XSS", Severity.HIGH, f"{B}/does-not-reflect", "x",
                metadata={"param": "q"})
    with _Server():
        res = v.run(f, _scope())
    assert res.status == "not_confirmed"


def test_exploit_plans_generated():
    r = ScanResult()
    r.add_finding(Finding("SQL injection candidate", Severity.CRITICAL,
                          "http://h/item?id=1", "x", metadata={"param": "id"}))
    r.add_finding(Finding("Apache Struts RCE (CVE-2017-5638)", Severity.HIGH,
                          "http://h:8080/up", "x", metadata={"template": "CVE-2017-5638"}))
    r.add_finding(Finding("SSH default credentials", Severity.HIGH, "h:22", "x"))
    n = exploit.build_plans(r, _scope(intrusive=True))
    assert n == 3
    tools = {p.tool for p in r.exploit_plans}
    assert tools == {"sqlmap", "metasploit", "hydra"}
    msf = next(p for p in r.exploit_plans if p.tool == "metasploit")
    assert "struts2_content_type_ognl" in msf.command_str()


def test_cors_and_ssrf_confirmed():
    from orchestrator.models import Finding, Severity
    with _Server():
        r = ScanResult()
        r.add_finding(Finding("CORS misconfiguration", Severity.MEDIUM, f"{B}/api", "x"))
        r.add_finding(Finding("SSRF candidate", Severity.HIGH, f"{B}/fetch?url=x", "x",
                              metadata={"param": "url", "oob_url": f"{B}/ssrf-canary"}))
        validators.validate_findings(r, _scope())
    by = {f.title: f.validation for f in r.findings}
    assert by["CORS misconfiguration"].status == "confirmed"
    assert "reflects arbitrary origin" in by["CORS misconfiguration"].evidence
    assert by["SSRF candidate"].status == "confirmed"


def _make_jwt(alg: str, secret: str = "") -> str:
    import base64, hashlib, hmac, json
    def b(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    header = b(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b(json.dumps({"user": "admin"}).encode())
    if alg == "none":
        return f"{header}.{payload}."
    mac = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b(mac)}"


def test_jwt_validator():
    from orchestrator.models import Finding, Severity
    r = ScanResult()
    r.add_finding(Finding("JWT weak secret", Severity.HIGH, "http://h/", "x",
                          metadata={"token": _make_jwt("HS256", "secret")}))
    r.add_finding(Finding("JWT alg none", Severity.HIGH, "http://h/", "x",
                          metadata={"token": _make_jwt("none")}))
    r.add_finding(Finding("JWT strong", Severity.HIGH, "http://h/", "x",
                          metadata={"token": _make_jwt("HS256", "a-very-long-random-secret-xyz")}))
    validators.validate_findings(r, _scope())
    by = {f.title: f.validation for f in r.findings}
    assert by["JWT weak secret"].status == "confirmed" and "secret" in by["JWT weak secret"].evidence
    assert by["JWT alg none"].status == "confirmed"
    assert by["JWT strong"].status == "not_confirmed"


def test_execution_gates():
    r = ScanResult()
    r.add_finding(Finding("SQL injection candidate", Severity.CRITICAL,
                          "http://127.0.0.1/item?id=1", "x", metadata={"param": "id"}))
    exploit.build_plans(r, _scope(intrusive=True))
    pid = r.exploit_plans[0].plan_id

    # gate: intrusive required
    p = exploit.execute_plan(r, pid, _scope(intrusive=False), confirm=True)
    assert p.status == "declined" and "not intrusive" in p.output

    # gate: explicit confirm required
    p = exploit.execute_plan(r, pid, _scope(intrusive=True), confirm=False)
    assert p.status == "declined" and "confirmation" in p.output

    # gate: out-of-scope target refused
    scope = Scope(name="x", authorized=True, hosts=["10.0.0.1"], intrusive=True)
    p = exploit.execute_plan(r, pid, scope, confirm=True)
    assert p.status == "declined" and "out of scope" in p.output


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
