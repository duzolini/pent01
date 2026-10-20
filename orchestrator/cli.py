"""Command-line entry point.

    orchestrator init-scope  scope.yaml
    orchestrator check-scope scope.yaml TARGET...
    orchestrator scan        scope.yaml [--yes] [--report out.html]
    orchestrator report      SCAN_ID [--format html|md] [-o FILE]
    orchestrator serve       [--host 127.0.0.1] [--port 8000]
    orchestrator list
"""

from __future__ import annotations

import argparse
import sys
import textwrap

from . import report, store
from .runner import Runner
from .scope import Scope, ScopeError

_EXAMPLE_SCOPE = textwrap.dedent("""\
    # Assessment scope — edit before use.
    name: example-engagement

    # The hard gate. Leave false until you hold WRITTEN authorization to test
    # every target below. The orchestrator refuses to scan while this is false.
    authorized: false

    # Authorization provenance — recorded into every scan's audit trail.
    client: ""
    authorized_by: ""
    authorization_ref: ""   # contract ID, ticket, or bug-bounty program URL
    expires: ""             # ISO date, informational

    # Allow-list. A target is scanned only if it matches here and is not excluded.
    domains:                # apex domains (subdomains included)
      - example.com
    hosts: []               # individual FQDNs or IPs
    cidrs: []               # e.g. 203.0.113.0/24
    exclude: []             # always-off hosts/IPs/CIDRs (wins over everything)

    # Safety knobs.
    rate_limit: 50          # req/s hint passed to tools
    max_concurrency: 10
    intrusive: false        # true enables fuzz/brute/dos templates AND active exploit plans
    validate: true          # run safe, non-destructive confirmation of findings
    oob_url: ""             # base URL of your OOB listener (for blind SSRF/XSS), e.g. http://1.2.3.4:8081

    # Optional — authenticated scanning (uncomment one):
    # auth: {type: bearer, token: "..."}
    # auth: {type: cookie, cookie: "session=..."}
    # auth: {type: basic, username: u, password: p}
    # auth: {type: form, login_url: "https://app/login", data: {user: u, pass: p}, success: "Welcome"}
    """)


def _cmd_init_scope(args: argparse.Namespace) -> int:
    from pathlib import Path
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"refusing to overwrite existing {path} (use --force)", file=sys.stderr)
        return 1
    path.write_text(_EXAMPLE_SCOPE)
    print(f"wrote example scope to {path}")
    print("Edit it, fill in the authorization fields, and set 'authorized: true'.")
    return 0


def _cmd_check_scope(args: argparse.Namespace) -> int:
    scope = Scope.load(args.path)
    print(f"scope: {scope.name}  (authorized={scope.authorized})")
    for t in args.targets:
        verdict = "IN SCOPE" if scope.is_in_scope(t) else "out of scope"
        print(f"  {t:40s} -> {verdict}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    scope = Scope.load(args.path)
    try:
        scope.require_authorized()
    except ScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(f"Scope '{scope.name}' authorized by: {scope.authorized_by or '(unspecified)'}")
    print(f"Targets: {', '.join(scope.seed_targets())}")
    if not args.yes:
        reply = input("Proceed with authorized scan of the above? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("aborted.")
            return 1

    _seen: set[str] = set()

    def progress(result) -> None:
        for s in result.stages:
            if s.status in ("ok", "skipped", "error") and s.tool not in _seen:
                _seen.add(s.tool)
                note = f" ({s.skipped_reason or s.error})" if s.status != "ok" else ""
                print(f"  [{s.stage}] {s.tool}: {s.status}{note}")

    result = Runner(scope).run(on_progress=progress)
    counts = result.severity_counts()
    print(f"\nScan {result.scan_id} {result.status}. "
          f"Assets: {len(result.assets)}  "
          f"Findings: crit={counts['critical']} high={counts['high']} "
          f"med={counts['medium']} low={counts['low']} info={counts['info']}")
    print(f"Saved to data/scans/{result.scan_id}.json")

    if args.report:
        out = args.report
        text = report.to_html(result) if out.endswith((".html", ".htm")) else report.to_markdown(result)
        from pathlib import Path
        Path(out).write_text(text)
        print(f"Report written to {out}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    from . import exploit, validators
    scope = Scope.load(args.path)
    result = store.load(args.scan_id)
    if result is None:
        print(f"no such scan: {args.scan_id}", file=sys.stderr)
        return 1
    print(f"Validating {len(result.findings)} findings against scope '{scope.name}' "
          "(safe, non-destructive)…")

    def show(f) -> None:
        v = f.validation
        mark = {"confirmed": "✔ CONFIRMED", "not_confirmed": "· not confirmed",
                "skipped": "- skipped", "error": "! error",
                "unverified": "? no auto-validator"}.get(v.status, v.status)
        print(f"  [{mark}] {f.title}  ({f.target})")
        if v.evidence:
            print(f"        evidence: {v.evidence}")

    confirmed = validators.validate_findings(result, scope, on_each=show)
    n = exploit.build_plans(result, scope)
    store.save(result)
    print(f"\n{confirmed} confirmed. {n} exploit plan(s) proposed — see "
          f"'orchestrator plans {result.scan_id}'.")
    return 0


def _cmd_plans(args: argparse.Namespace) -> int:
    result = store.load(args.scan_id)
    if result is None:
        print(f"no such scan: {args.scan_id}", file=sys.stderr)
        return 1
    if not result.exploit_plans:
        print("no exploit plans. Run 'validate' first, or no findings are exploitable.")
        return 0
    for p in result.exploit_plans:
        f = result.finding_by_id(p.finding_id)
        print(f"\n[{p.plan_id}] {p.tool}  — status: {p.status}")
        print(f"  finding : {f.title if f else p.finding_id}")
        print(f"  why     : {p.rationale}")
        print(f"  risk    : {p.risk}")
        print(f"  command : {p.command_str()}")
    print("\nTo run one (requires intrusive: true + explicit confirm):")
    print(f"  orchestrator exploit <scope.yaml> {result.scan_id} <plan_id> --confirm")
    return 0


def _cmd_exploit(args: argparse.Namespace) -> int:
    from . import exploit
    scope = Scope.load(args.path)
    result = store.load(args.scan_id)
    if result is None:
        print(f"no such scan: {args.scan_id}", file=sys.stderr)
        return 1
    plan = result.plan_by_id(args.plan_id)
    if plan is None:
        print(f"no such plan: {args.plan_id}", file=sys.stderr)
        return 1

    print(f"Plan [{plan.plan_id}] {plan.tool}")
    print(f"  command: {plan.command_str()}")
    print(f"  risk   : {plan.risk}")
    if not args.confirm:
        print("\nNot executed. Re-run with --confirm to execute "
              "(scope must also have intrusive: true).")
        return 0
    if not scope.intrusive:
        print("\nRefused: scope is not intrusive. Set 'intrusive: true' only with "
              "explicit authorization for active exploitation.", file=sys.stderr)
        return 2
    # Final interactive gate.
    typed = input(f"Type the plan id '{plan.plan_id}' to execute: ").strip()
    if typed != plan.plan_id:
        print("confirmation mismatch; aborted.")
        return 1
    plan = exploit.execute_plan(result, plan.plan_id, scope, confirm=True)
    store.save(result)
    print(f"\nstatus: {plan.status}")
    print(plan.output)
    return 0 if plan.status == "executed" else 1


def _cmd_diff(args: argparse.Namespace) -> int:
    from . import diff
    old = store.load(args.old)
    new = store.load(args.new)
    if old is None or new is None:
        print("one or both scan ids not found", file=sys.stderr)
        return 1
    print(diff.render(diff.diff_scans(old, new)))
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    import time
    from . import diff
    scope = Scope.load(args.path)
    try:
        scope.require_authorized()
    except ScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Watching scope '{scope.name}' every {args.interval}s "
          f"({'unlimited' if args.max_runs == 0 else args.max_runs} runs). Ctrl-C to stop.")
    run = 0
    try:
        while args.max_runs == 0 or run < args.max_runs:
            run += 1
            prev = store.scans_for_scope(scope.name)
            prev = prev[0] if prev else None
            print(f"\n[run {run}] starting scan…")
            result = Runner(scope).run()
            if prev:
                d = diff.diff_scans(prev, result)
                print(diff.render(d))
                if d.new_findings:
                    print(f"\n⚠ ALERT: {len(d.new_findings)} new finding(s) since last scan.")
            else:
                print(f"baseline scan {result.scan_id}: {len(result.findings)} findings.")
            if args.max_runs != 0 and run >= args.max_runs:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from . import export as exp
    result = store.load(args.scan_id)
    if result is None:
        print(f"no such scan: {args.scan_id}", file=sys.stderr)
        return 1
    try:
        text = exp.export(result, args.format)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text)
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    result = store.load(args.scan_id)
    if result is None:
        print(f"no such scan: {args.scan_id}", file=sys.stderr)
        return 1
    text = report.to_html(result) if args.format == "html" else report.to_markdown(result)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text)
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    scans = store.list_scans()
    if not scans:
        print("no scans yet.")
        return 0
    for s in scans:
        c = s.severity_counts()
        print(f"{s.scan_id}  {s.scope_name:24s} {s.status:8s} "
              f"findings={len(s.findings):<3d} (H{c['high']}/M{c['medium']}) "
              f"assets={len(s.assets)}")
    return 0


def _cmd_oob_listen(args: argparse.Namespace) -> int:
    from .oob import OobListener, DEFAULT_LOG
    base = args.base_url or f"http://{args.host}:{args.port}"
    listener = OobListener(host=args.host, port=args.port)
    print(f"OOB listener on {args.host}:{args.port}")
    print(f"  base URL (put this in your scope's oob_url): {base}")
    print(f"  interactions logged to: {DEFAULT_LOG}")
    print("  waiting for callbacks… (Ctrl-C to stop)")
    try:
        listener.serve_forever()
    except KeyboardInterrupt:
        listener.shutdown()
        print("\nstopped.")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .web.app import create_app
    app = create_app()
    print(f"Dashboard on http://{args.host}:{args.port}  (Ctrl-C to stop)")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orchestrator",
                                description="Authorized assessment orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-scope", help="write an example scope file")
    s.add_argument("path")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=_cmd_init_scope)

    s = sub.add_parser("check-scope", help="test whether targets are in scope")
    s.add_argument("path")
    s.add_argument("targets", nargs="+")
    s.set_defaults(func=_cmd_check_scope)

    s = sub.add_parser("scan", help="run the pipeline against an authorized scope")
    s.add_argument("path")
    s.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    s.add_argument("--report", help="also write a report to this file (.html or .md)")
    s.set_defaults(func=_cmd_scan)

    s = sub.add_parser("validate", help="safely confirm a scan's findings (non-destructive)")
    s.add_argument("path", help="scope file")
    s.add_argument("scan_id")
    s.set_defaults(func=_cmd_validate)

    s = sub.add_parser("plans", help="list proposed operator-in-the-loop exploit plans")
    s.add_argument("scan_id")
    s.set_defaults(func=_cmd_plans)

    s = sub.add_parser("exploit", help="execute one exploit plan (gated: intrusive + confirm)")
    s.add_argument("path", help="scope file")
    s.add_argument("scan_id")
    s.add_argument("plan_id")
    s.add_argument("--confirm", action="store_true", help="actually execute (still prompts)")
    s.set_defaults(func=_cmd_exploit)

    s = sub.add_parser("diff", help="compare two scans (new / resolved findings)")
    s.add_argument("old")
    s.add_argument("new")
    s.set_defaults(func=_cmd_diff)

    s = sub.add_parser("watch", help="continuous assessment: rescan on an interval and diff")
    s.add_argument("path", help="scope file")
    s.add_argument("--interval", type=int, default=3600, help="seconds between runs")
    s.add_argument("--max-runs", type=int, default=0, help="stop after N runs (0 = unlimited)")
    s.set_defaults(func=_cmd_watch)

    s = sub.add_parser("export", help="export findings (sarif/json/csv/defectdojo)")
    s.add_argument("scan_id")
    s.add_argument("--format", choices=["sarif", "json", "csv", "defectdojo"], default="sarif")
    s.add_argument("-o", "--output")
    s.set_defaults(func=_cmd_export)

    s = sub.add_parser("report", help="render a stored scan as a report")
    s.add_argument("scan_id")
    s.add_argument("--format", choices=["html", "md"], default="html")
    s.add_argument("-o", "--output")
    s.set_defaults(func=_cmd_report)

    s = sub.add_parser("list", help="list stored scans")
    s.set_defaults(func=_cmd_list)

    s = sub.add_parser("oob-listen", help="run the out-of-band listener for blind vuln confirmation")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8081)
    s.add_argument("--base-url", help="public URL the target can reach (default http://host:port)")
    s.set_defaults(func=_cmd_oob_listen)

    s = sub.add_parser("serve", help="run the web dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=_cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
