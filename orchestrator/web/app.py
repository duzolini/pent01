"""Flask dashboard: pick an authorized scope, launch a scan, watch results.

The web layer is deliberately thin. It never bypasses the scope gate: a scan
launched from the UI goes through the same ``Runner`` and the same
``require_authorized()`` check as the CLI. The server binds to localhost by
default — this is an operator console, not a public service.
"""

from __future__ import annotations

import threading
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template,
                   request, url_for, Response)

from .. import report, store
from ..runner import Runner
from ..scope import Scope, ScopeError

SCOPES_DIR = Path(__file__).resolve().parents[2] / "scopes"

# Track running scans so the UI can show live status without a job queue.
_running: dict[str, threading.Thread] = {}
_lock = threading.Lock()


def _discover_scopes() -> list[Path]:
    SCOPES_DIR.mkdir(exist_ok=True)
    return sorted(SCOPES_DIR.glob("*.y*ml"))


def _scope_for(result) -> Scope | None:
    """Find the scope file whose name matches the scan's scope_name."""
    for p in _discover_scopes():
        try:
            s = Scope.load(p)
        except ScopeError:
            continue
        if s.name == result.scope_name:
            return s
    return None


def _launch(scope: Scope) -> str:
    runner = Runner(scope)
    result_holder: dict[str, str] = {}

    def worker() -> None:
        res = runner.run()
        result_holder["id"] = res.scan_id

    # Create the scan row synchronously first so the redirect has an id.
    scope.require_authorized()
    thread = threading.Thread(target=worker, daemon=True)
    with _lock:
        thread.start()
    # Give the worker a moment to persist the initial record.
    thread.join(timeout=0.5)
    scans = store.list_scans()
    latest = scans[0].scan_id if scans else ""
    with _lock:
        _running[latest] = thread
    return latest


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = "assessment-orchestrator-local"  # local console only

    @app.route("/")
    def index():
        scopes = _discover_scopes()
        parsed = []
        for p in scopes:
            try:
                s = Scope.load(p)
                parsed.append({"path": p.name, "name": s.name,
                               "authorized": s.authorized,
                               "targets": ", ".join(s.seed_targets())})
            except ScopeError as exc:
                parsed.append({"path": p.name, "name": p.stem,
                               "authorized": False, "targets": f"(invalid: {exc})"})
        return render_template("index.html", scopes=parsed, scans=store.list_scans())

    @app.route("/scan", methods=["POST"])
    def scan():
        scope_file = request.form.get("scope_file", "")
        confirm = request.form.get("confirm") == "on"
        path = SCOPES_DIR / scope_file
        if not path.exists():
            flash("scope file not found", "error")
            return redirect(url_for("index"))
        try:
            scope = Scope.load(path)
            scope.require_authorized()
        except ScopeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        if not confirm:
            flash("You must confirm you are authorized to test these targets.", "error")
            return redirect(url_for("index"))
        scan_id = _launch(scope)
        flash(f"Scan started for scope '{scope.name}'.", "ok")
        return redirect(url_for("detail", scan_id=scan_id) if scan_id else url_for("index"))

    @app.route("/scan/<scan_id>")
    def detail(scan_id: str):
        result = store.load(scan_id)
        if result is None:
            abort(404)
        live = result.status == "running"
        scope = _scope_for(result)
        validated = any(f.validation for f in result.findings)
        prev = store.previous_scan(result)
        scandiff = None
        if prev and not live:
            from .. import diff as diffmod
            scandiff = diffmod.diff_scans(prev, result)
        return render_template("scan.html", r=result, live=live,
                               intrusive=bool(scope and scope.intrusive),
                               validated=validated, diff=scandiff)

    @app.route("/scan/<scan_id>/validate", methods=["POST"])
    def validate(scan_id: str):
        from .. import exploit, validators
        result = store.load(scan_id)
        if result is None:
            abort(404)
        scope = _scope_for(result)
        if scope is None:
            flash(f"no scope file named '{result.scope_name}' to validate against.", "error")
            return redirect(url_for("detail", scan_id=scan_id))
        try:
            n = validators.validate_findings(result, scope)
            exploit.build_plans(result, scope)
            store.save(result)
            flash(f"Validated: {n} finding(s) confirmed, {len(result.exploit_plans)} "
                  "exploit plan(s) proposed.", "ok")
        except ScopeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("detail", scan_id=scan_id))

    @app.route("/scan/<scan_id>/exploit/<plan_id>", methods=["POST"])
    def run_exploit(scan_id: str, plan_id: str):
        from .. import exploit
        result = store.load(scan_id)
        if result is None:
            abort(404)
        plan = result.plan_by_id(plan_id)
        if plan is None:
            abort(404)
        scope = _scope_for(result)
        if scope is None:
            flash("no scope file to authorize this execution.", "error")
            return redirect(url_for("detail", scan_id=scan_id))
        # The typed confirmation must exactly equal the plan id.
        typed = request.form.get("confirm_id", "").strip()
        if typed != plan_id:
            flash("Confirmation mismatch — type the exact plan id to execute.", "error")
            return redirect(url_for("detail", scan_id=scan_id))
        plan = exploit.execute_plan(result, plan_id, scope, confirm=True)
        store.save(result)
        flash(f"Plan {plan_id}: {plan.status}.",
              "ok" if plan.status == "executed" else "error")
        return redirect(url_for("detail", scan_id=scan_id))

    @app.route("/scan/<scan_id>/report.html")
    def report_html(scan_id: str):
        result = store.load(scan_id)
        if result is None:
            abort(404)
        return Response(report.to_html(result), mimetype="text/html")

    @app.route("/scan/<scan_id>/report.md")
    def report_md(scan_id: str):
        result = store.load(scan_id)
        if result is None:
            abort(404)
        return Response(report.to_markdown(result), mimetype="text/plain")

    return app
