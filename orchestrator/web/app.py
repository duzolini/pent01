"""Flask dashboard: pick an authorized scope, launch a scan, watch results.

The web layer is deliberately thin. It never bypasses the scope gate: a scan
launched from the UI goes through the same ``Runner`` and the same
``require_authorized()`` check as the CLI. The server binds to localhost by
default — this is an operator console, not a public service.
"""

from __future__ import annotations

import threading
from pathlib import Path

import yaml
from flask import (Flask, abort, flash, redirect, render_template,
                   request, url_for, Response)

from .. import report, store
from ..runner import Runner
from ..scheduler import Scheduler
from ..scope import Scope, ScopeError

SCOPES_DIR = Path(__file__).resolve().parents[2] / "scopes"

# Track running scans so the UI can show live status without a job queue.
_running: dict[str, threading.Thread] = {}
_lock = threading.Lock()

# Continuous-assessment scheduler and OOB listener, both managed from the UI.
_scheduler = Scheduler()
_oob: dict[str, object] = {"listener": None, "thread": None, "port": None}


def _list_field(raw: str) -> list[str]:
    """Split a textarea/CSV field into a clean list."""
    items: list[str] = []
    for chunk in (raw or "").replace(",", "\n").splitlines():
        v = chunk.strip()
        if v:
            items.append(v)
    return items


def _auth_from_form(form) -> dict:
    """Build the scope's auth block from the form's authenticated-scanning fields."""
    kind = (form.get("auth_type") or "").strip().lower()
    if kind in ("", "none"):
        return {}
    if kind == "bearer":
        return {"type": "bearer", "token": form.get("auth_token", "").strip()}
    if kind == "cookie":
        return {"type": "cookie", "cookie": form.get("auth_cookie", "").strip()}
    if kind == "basic":
        return {"type": "basic", "username": form.get("auth_username", "").strip(),
                "password": form.get("auth_password", "").strip()}
    if kind == "form":
        return {"type": "form", "login_url": form.get("auth_login_url", "").strip(),
                "data": {form.get("auth_user_field", "username"): form.get("auth_username", "").strip(),
                         form.get("auth_pass_field", "password"): form.get("auth_password", "").strip()},
                "success": form.get("auth_success", "").strip()}
    return {}


def _write_scope(filename: str, form) -> Path:
    """Build a scope YAML from submitted form fields and write it."""
    if not filename.endswith((".yaml", ".yml")):
        filename += ".yaml"
    # Keep the filename safe — no path traversal.
    filename = Path(filename).name
    data = {
        "name": (form.get("name") or Path(filename).stem).strip(),
        "authorized": form.get("authorized") == "on",
        "client": form.get("client", "").strip(),
        "authorized_by": form.get("authorized_by", "").strip(),
        "authorization_ref": form.get("authorization_ref", "").strip(),
        "expires": form.get("expires", "").strip(),
        "domains": _list_field(form.get("domains", "")),
        "hosts": _list_field(form.get("hosts", "")),
        "cidrs": _list_field(form.get("cidrs", "")),
        "exclude": _list_field(form.get("exclude", "")),
        "rate_limit": int(form.get("rate_limit") or 50),
        "max_concurrency": int(form.get("max_concurrency") or 10),
        "intrusive": form.get("intrusive") == "on",
        "validate": form.get("validate") == "on",
        "oob_url": form.get("oob_url", "").strip(),
        "auth": _auth_from_form(form),
    }
    if not data["auth"]:
        data.pop("auth")
    # Validate before writing so the UI can reject bad input.
    Scope(name=data["name"], authorized=data["authorized"], domains=data["domains"],
          hosts=data["hosts"], cidrs=data["cidrs"])
    path = SCOPES_DIR / filename
    SCOPES_DIR.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return path


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
        from .. import owasp
        return render_template("scan.html", r=result, live=live,
                               intrusive=bool(scope and scope.intrusive),
                               validated=validated, diff=scandiff,
                               owasp_rows=owasp.coverage(result),
                               owasp_cats=owasp.CATEGORIES)

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

    @app.route("/scan/<scan_id>/export/<fmt>")
    def export_scan(scan_id: str, fmt: str):
        from .. import export as exp
        result = store.load(scan_id)
        if result is None:
            abort(404)
        try:
            text = exp.export(result, fmt)
        except ValueError:
            abort(404)
        mime = "text/csv" if fmt == "csv" else "application/json"
        fname = exp.FORMATS[fmt][1]
        return Response(text, mimetype=mime,
                        headers={"Content-Disposition":
                                 f"attachment; filename={scan_id[:8]}-{fname}"})

    # ---- Scope management (no YAML editing by hand) ----
    @app.route("/scopes")
    def scopes_page():
        rows = []
        for p in _discover_scopes():
            try:
                s = Scope.load(p)
                rows.append({"path": p.name, "name": s.name, "authorized": s.authorized,
                             "targets": ", ".join(s.seed_targets()), "intrusive": s.intrusive})
            except ScopeError as exc:
                rows.append({"path": p.name, "name": p.stem, "authorized": False,
                             "targets": f"(invalid: {exc})", "intrusive": False})
        return render_template("scopes.html", scopes=rows)

    @app.route("/scopes/new", methods=["GET", "POST"])
    def scope_new():
        if request.method == "POST":
            try:
                path = _write_scope(request.form.get("filename", "scope.yaml"), request.form)
                flash(f"Scope saved to {path.name}.", "ok")
                return redirect(url_for("scopes_page"))
            except (ScopeError, ValueError) as exc:
                flash(f"Could not save scope: {exc}", "error")
        return render_template("scope_form.html", scope=None, filename="")

    @app.route("/scopes/<filename>/edit", methods=["GET", "POST"])
    def scope_edit(filename: str):
        path = SCOPES_DIR / Path(filename).name
        if not path.exists():
            abort(404)
        if request.method == "POST":
            try:
                _write_scope(filename, request.form)
                flash("Scope updated.", "ok")
                return redirect(url_for("scopes_page"))
            except (ScopeError, ValueError) as exc:
                flash(f"Could not save scope: {exc}", "error")
        import yaml as _yaml
        data = _yaml.safe_load(path.read_text()) or {}
        return render_template("scope_form.html", scope=data, filename=filename)

    @app.route("/scopes/<filename>/delete", methods=["POST"])
    def scope_delete(filename: str):
        path = SCOPES_DIR / Path(filename).name
        if path.exists():
            path.unlink()
            flash(f"Deleted {path.name}.", "ok")
        return redirect(url_for("scopes_page"))

    # ---- OOB listener control ----
    @app.route("/oob", methods=["GET"])
    def oob_page():
        from ..oob import DEFAULT_LOG
        interactions = []
        if DEFAULT_LOG.exists():
            import json
            for line in DEFAULT_LOG.read_text().splitlines()[-50:]:
                try:
                    interactions.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        interactions.reverse()
        return render_template("oob.html", running=bool(_oob["listener"]),
                               port=_oob["port"], interactions=interactions)

    @app.route("/oob/start", methods=["POST"])
    def oob_start():
        from ..oob import OobListener
        if _oob["listener"]:
            flash("OOB listener already running.", "error")
            return redirect(url_for("oob_page"))
        port = int(request.form.get("port") or 8081)
        try:
            listener = OobListener(host="0.0.0.0", port=port)
        except OSError as exc:
            flash(f"Could not bind port {port}: {exc}", "error")
            return redirect(url_for("oob_page"))
        t = threading.Thread(target=listener.serve_forever, daemon=True)
        t.start()
        _oob.update(listener=listener, thread=t, port=port)
        flash(f"OOB listener started on port {port}. Set oob_url in your scope to reach it.", "ok")
        return redirect(url_for("oob_page"))

    @app.route("/oob/stop", methods=["POST"])
    def oob_stop():
        listener = _oob["listener"]
        if listener:
            listener.shutdown()
            _oob.update(listener=None, thread=None, port=None)
            flash("OOB listener stopped.", "ok")
        return redirect(url_for("oob_page"))

    # ---- Diff any two scans ----
    @app.route("/diff")
    def diff_page():
        from .. import diff as diffmod
        scans = store.list_scans()
        old_id, new_id = request.args.get("old"), request.args.get("new")
        result = None
        if old_id and new_id:
            old, new = store.load(old_id), store.load(new_id)
            if old and new:
                result = diffmod.diff_scans(old, new)
        return render_template("diff.html", scans=scans, diff=result,
                               old_id=old_id, new_id=new_id)

    # ---- Continuous assessment ----
    @app.route("/watch")
    def watch_page():
        return render_template("watch.html", watchers=_scheduler.list(),
                               scopes=[{"path": p.name, "name": Scope.load(p).name}
                                       for p in _discover_scopes()
                                       if _safe_scope(p)])

    @app.route("/watch/start", methods=["POST"])
    def watch_start():
        path = SCOPES_DIR / Path(request.form.get("scope_file", "")).name
        if not path.exists():
            flash("scope file not found", "error")
            return redirect(url_for("watch_page"))
        try:
            scope = Scope.load(path)
            interval = int(request.form.get("interval") or 3600)
            _scheduler.start(scope, str(path), interval)
            flash(f"Continuous assessment started for '{scope.name}' every {max(60, interval)}s.", "ok")
        except ScopeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("watch_page"))

    @app.route("/watch/stop", methods=["POST"])
    def watch_stop():
        name = request.form.get("scope_name", "")
        if _scheduler.stop(name):
            flash(f"Stopped watching '{name}'.", "ok")
        return redirect(url_for("watch_page"))

    return app


def _safe_scope(path) -> bool:
    try:
        Scope.load(path)
        return True
    except ScopeError:
        return False
