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
    intrusive: false        # true enables fuzz/brute/dos nuclei templates
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

    s = sub.add_parser("report", help="render a stored scan as a report")
    s.add_argument("scan_id")
    s.add_argument("--format", choices=["html", "md"], default="html")
    s.add_argument("-o", "--output")
    s.set_defaults(func=_cmd_report)

    s = sub.add_parser("list", help="list stored scans")
    s.set_defaults(func=_cmd_list)

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
