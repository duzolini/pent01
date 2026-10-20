"""Tests for the OOB listener (blind confirmation) and scan diffing."""

import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools_demo"))

from werkzeug.serving import make_server  # noqa: E402

import orchestrator.oob as oob  # noqa: E402
from orchestrator import diff, validators  # noqa: E402
from orchestrator.models import Asset, Finding, ScanResult, Severity  # noqa: E402
from orchestrator.scope import Scope  # noqa: E402

OOB_PORT = 8097
APP_PORT = 5097


def _isolate_log(tmp):
    oob.DEFAULT_LOG = Path(tmp) / "interactions.jsonl"
    return oob.DEFAULT_LOG


def test_oob_listener_records_and_client_reads(tmp_path):
    _isolate_log(tmp_path)
    listener = oob.OobListener("127.0.0.1", OOB_PORT)
    th = threading.Thread(target=listener.serve_forever, daemon=True)
    th.start()
    time.sleep(0.3)
    try:
        client = oob.OobClient(f"http://127.0.0.1:{OOB_PORT}")
        token = client.new_token()
        urllib.request.urlopen(client.callback_url(token), timeout=5).read()
        hits = client.wait_for(token, timeout=4)
        assert hits and hits[0]["token"] == token
        assert hits[0]["src_ip"] == "127.0.0.1"
    finally:
        listener.shutdown()


def test_blind_ssrf_confirmed_via_oob(tmp_path):
    _isolate_log(tmp_path)
    from vuln_app import app
    srv = make_server("127.0.0.1", APP_PORT, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    listener = oob.OobListener("127.0.0.1", OOB_PORT + 1)
    threading.Thread(target=listener.serve_forever, daemon=True).start()
    time.sleep(0.4)
    try:
        scope = Scope(name="lab", authorized=True, hosts=["127.0.0.1"],
                      oob_url=f"http://127.0.0.1:{OOB_PORT + 1}")
        r = ScanResult()
        r.add_finding(Finding("SSRF candidate", Severity.HIGH,
                              f"http://127.0.0.1:{APP_PORT}/fetch-blind?url=x", "x",
                              metadata={"param": "url"}))
        validators.validate_findings(r, scope)
        v = r.findings[0].validation
        assert v.status == "confirmed", v.detail
        assert "OOB callback" in v.evidence
    finally:
        listener.shutdown()
        srv.shutdown()


def _scan(findings):
    r = ScanResult(scope_name="s")
    for f in findings:
        r.add_finding(f)
    return r


def test_diff_new_and_resolved():
    old = _scan([
        Finding("SQLi", Severity.CRITICAL, "http://h/a", "x"),
        Finding("XSS", Severity.HIGH, "http://h/b", "x"),
    ])
    new = _scan([
        Finding("XSS", Severity.HIGH, "http://h/b", "x"),           # unchanged
        Finding("Open redirect", Severity.MEDIUM, "http://h/c", "x"),  # new
    ])
    new.add_asset(Asset("url", "http://h/new", "httpx"))
    d = diff.diff_scans(old, new)
    assert [f.title for f in d.new_findings] == ["Open redirect"]
    assert [f.title for f in d.resolved_findings] == ["SQLi"]
    assert [f.title for f in d.unchanged_findings] == ["XSS"]
    assert len(d.new_assets) == 1
    assert d.changed and "+1 new" in d.summary()


if __name__ == "__main__":
    import tempfile
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        if "tmp_path" in fn.__code__.co_varnames:
            with tempfile.TemporaryDirectory() as td:
                fn(td)
        else:
            fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
