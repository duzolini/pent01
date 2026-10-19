"""Fast smoke tests for the scope gate, serialization, and report rendering.

Run with:  python3 -m pytest -q   (or)   python3 tests/test_smoke.py
These tests make no network calls.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import report  # noqa: E402
from orchestrator.models import Finding, Severity, ScanResult, Asset  # noqa: E402
from orchestrator.scope import Scope, ScopeError  # noqa: E402


def _scope(**kw):
    base = dict(name="t", authorized=True, domains=["example.com"],
                hosts=["10.0.0.5"], cidrs=["192.168.1.0/24"], exclude=["admin.example.com"])
    base.update(kw)
    return Scope(**base)


def test_scope_membership():
    s = _scope()
    assert s.is_in_scope("example.com")
    assert s.is_in_scope("api.example.com")          # subdomain
    assert s.is_in_scope("https://www.example.com/x")  # URL
    assert s.is_in_scope("10.0.0.5")                 # host
    assert s.is_in_scope("192.168.1.42")             # CIDR
    assert not s.is_in_scope("evil.com")
    assert not s.is_in_scope("10.0.0.6")
    assert not s.is_in_scope("admin.example.com")    # excluded
    assert not s.is_in_scope("192.168.2.1")


def test_authorization_gate():
    s = _scope(authorized=False)
    raised = False
    try:
        s.require_authorized()
    except ScopeError:
        raised = True
    assert raised, "unauthorized scope must refuse to run"
    _scope(authorized=True).require_authorized()  # must not raise


def test_invalid_scope_rejected():
    for bad in (dict(domains=[], hosts=[], cidrs=[]), dict(cidrs=["999.0.0.0/8"])):
        try:
            _scope(**bad)
        except ScopeError:
            continue
        raise AssertionError(f"expected ScopeError for {bad}")


def test_scanresult_roundtrip_and_report():
    r = ScanResult(scope_name="t", targets=["example.com"], status="done")
    r.add_asset(Asset("url", "https://example.com", source="httpx",
                      metadata={"status_code": 200, "title": "Example"}))
    r.add_asset(Asset("url", "https://example.com", source="httpx"))  # dup ignored
    r.add_finding(Finding("Missing HSTS", Severity.MEDIUM, "https://example.com", "http-headers"))
    r.add_finding(Finding("Critical RCE", Severity.CRITICAL, "https://example.com", "nuclei"))
    assert len(r.assets) == 1
    assert r.severity_counts()["critical"] == 1
    assert r.sorted_findings()[0].severity is Severity.CRITICAL

    restored = ScanResult.from_dict(r.to_dict())
    assert restored.scope_name == "t"
    assert restored.severity_counts() == r.severity_counts()

    html = report.to_html(r)
    assert "Critical RCE" in html and "Missing HSTS" in html
    md = report.to_markdown(r)
    assert "# Assessment report" in md and "CRITICAL" in md


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
