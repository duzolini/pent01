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
        return render_template("scan.html", r=result, live=live)

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
