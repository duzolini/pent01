"""Render a scan result as Markdown or a self-contained HTML report."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .models import ScanResult, Severity

_SEV_COLOR = {
    "critical": "#7c1d1d", "high": "#b4232a", "medium": "#c77700",
    "low": "#2d6cb3", "info": "#5b6470",
}


def _ts(value: float | None) -> str:
    if not value:
        return "—"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------- #
def to_markdown(r: ScanResult) -> str:
    counts = r.severity_counts()
    lines = [
        f"# Assessment report — {r.scope_name}",
        "",
        f"- **Scan ID:** `{r.scan_id}`",
        f"- **Status:** {r.status}",
        f"- **Started:** {_ts(r.created_at)}  |  **Finished:** {_ts(r.finished_at)}",
        f"- **Targets:** {', '.join(r.targets) or '—'}",
        "",
        "## Authorization",
    ]
    auth = r.authorization or {}
    for k in ("client", "authorized_by", "authorization_ref", "expires"):
        lines.append(f"- **{k.replace('_', ' ').title()}:** {auth.get(k) or '—'}")
    lines += [
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in reversed(list(Severity)):
        lines.append(f"| {sev.value.title()} | {counts[sev.value]} |")
    lines += ["", f"**Assets discovered:** {len(r.assets)}", ""]

    from . import owasp
    lines += ["## OWASP Top 10 (2021) coverage", "",
              "| Cat | Category | Findings | Confirmed |", "|-----|----------|---------:|----------:|"]
    for row in owasp.coverage(r):
        count = row["count"] or "—"
        conf = row["confirmed"] if row["count"] else "—"
        lines.append(f"| {row['id']} | {row['title']} | {count} | {conf} |")
    lines.append("")

    lines += ["## Findings", ""]
    if not r.findings:
        lines.append("_No findings recorded._")
    for f in r.sorted_findings():
        vtag = f" — _{f.validation.status}_" if f.validation else ""
        lines += [
            f"### [{f.severity.value.upper()}] {f.title}{vtag}",
            f"- **Target:** `{f.target}`",
            f"- **Tool:** {f.tool}",
        ]
        if f.description:
            lines.append(f"- **Description:** {f.description}")
        if f.validation and (f.validation.evidence or f.validation.detail):
            lines.append(f"- **Validation:** `{f.validation.evidence or f.validation.detail}`")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence}`")
        if f.reference:
            lines.append(f"- **Reference:** {f.reference}")
        lines.append("")

    if r.exploit_plans:
        lines += ["## Exploit plans (operator-in-the-loop)", ""]
        for p in r.exploit_plans:
            fnd = r.finding_by_id(p.finding_id)
            lines += [
                f"### {p.tool} — {fnd.title if fnd else p.finding_id} ({p.status})",
                f"- **Why:** {p.rationale}",
                f"- **Risk:** {p.risk}",
                f"- **Command:** `{p.command_str()}`",
                "",
            ]

    lines += ["## Assets", ""]
    for kind in ("subdomain", "host", "service", "url"):
        items = r.assets_of(kind)
        if not items:
            continue
        lines.append(f"### {kind.title()}s ({len(items)})")
        for a in items:
            extra = ""
            if a.kind == "url" and a.metadata.get("status_code"):
                extra = f" — {a.metadata.get('status_code')} {a.metadata.get('title') or ''}"
            lines.append(f"- `{a.value}`{extra}")
        lines.append("")

    lines += ["## Tool runs", "", "| Stage | Tool | Status | Note |",
              "|-------|------|--------|------|"]
    for s in r.stages:
        note = s.skipped_reason or s.error or ""
        lines.append(f"| {s.stage} | {s.tool} | {s.status} | {note} |")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------- #
def to_html(r: ScanResult) -> str:
    counts = r.severity_counts()
    e = html.escape

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s.value]}">'
        f'{s.value.title()}: {counts[s.value]}</span>'
        for s in reversed(list(Severity))
    )

    _VCOLOR = {"confirmed": "#2e7d32", "not_confirmed": "#5b6470", "skipped": "#5b6470",
               "error": "#b4232a", "unverified": "#8a8f98"}
    finding_rows = ""
    for f in r.sorted_findings():
        v = f.validation
        vbadge = ""
        vevidence = ""
        if v:
            vbadge = (f'<span class="vbadge" style="background:{_VCOLOR.get(v.status, "#5b6470")}">'
                      f'{"✓ confirmed" if v.status == "confirmed" else e(v.status)}</span>')
            proof = v.evidence or v.detail
            if proof:
                vevidence = f'<div><span class="label">Validation</span> <code>{e(proof)}</code></div>'
        finding_rows += f"""
        <div class="finding sev-{f.severity.value}">
          <div class="finding-head">
            <span class="sev-badge" style="background:{_SEV_COLOR[f.severity.value]}">
              {f.severity.value.upper()}</span>
            <strong>{e(f.title)}</strong>
            {vbadge}
          </div>
          <div class="finding-body">
            <div><span class="label">Target</span> <code>{e(f.target)}</code></div>
            <div><span class="label">Tool</span> {e(f.tool)}</div>
            {f'<div><span class="label">Description</span> {e(f.description)}</div>' if f.description else ''}
            {vevidence}
            {f'<div><span class="label">Evidence</span> <code>{e(f.evidence)}</code></div>' if f.evidence else ''}
            {f'<div><span class="label">Reference</span> {e(f.reference)}</div>' if f.reference else ''}
          </div>
        </div>"""
    if not r.findings:
        finding_rows = '<p class="muted">No findings recorded.</p>'

    plan_rows = ""
    for p in r.exploit_plans:
        fnd = r.finding_by_id(p.finding_id)
        plan_rows += f"""
        <div class="finding">
          <div class="finding-head"><span class="sev-badge" style="background:#444c56">{e(p.tool)}</span>
            <strong>{e(fnd.title if fnd else p.finding_id)}</strong>
            <span class="vbadge" style="background:#5b6470">{e(p.status)}</span></div>
          <div class="finding-body">
            <div><span class="label">Why</span> {e(p.rationale)}</div>
            <div><span class="label">Risk</span> {e(p.risk)}</div>
            <div><span class="label">Command</span> <code>{e(p.command_str())}</code></div>
          </div>
        </div>"""

    asset_blocks = ""
    for kind in ("subdomain", "host", "service", "url"):
        items = r.assets_of(kind)
        if not items:
            continue
        rows = ""
        for a in items:
            meta = ""
            if a.kind == "url":
                meta = f"{a.metadata.get('status_code') or ''} {e(str(a.metadata.get('title') or ''))}"
            rows += f"<tr><td><code>{e(a.value)}</code></td><td>{meta}</td><td class='muted'>{e(a.source)}</td></tr>"
        asset_blocks += f"""
        <h3>{kind.title()}s <span class="muted">({len(items)})</span></h3>
        <table><tbody>{rows}</tbody></table>"""

    stage_rows = ""
    for s in r.stages:
        note = e(s.skipped_reason or s.error or "")
        cls = {"ok": "s-ok", "skipped": "s-skip", "error": "s-err"}.get(s.status, "")
        stage_rows += (f"<tr><td>{e(s.stage)}</td><td>{e(s.tool)}</td>"
                       f"<td class='{cls}'>{e(s.status)}</td><td class='muted'>{note}</td></tr>")

    from . import owasp
    owasp_rows = ""
    for row in owasp.coverage(r):
        if row["count"]:
            sev = row["top_severity"]
            badge = (f'<span class="sev-badge" style="background:{_SEV_COLOR.get(sev, "#5b6470")}">'
                     f'{sev.upper()}</span>' if sev else "")
            status = f'{row["confirmed"]}/{row["count"]} confirmed'
        else:
            badge, status = '<span class="muted">—</span>', '<span class="muted">no findings</span>'
        owasp_rows += (f'<tr><td><code>{row["id"]}</code></td><td>{e(row["title"])}</td>'
                       f'<td>{badge}</td><td>{status}</td></tr>')

    auth = r.authorization or {}
    auth_rows = "".join(
        f"<div><span class='label'>{k.replace('_',' ').title()}</span> {e(str(auth.get(k) or '—'))}</div>"
        for k in ("client", "authorized_by", "authorization_ref", "expires")
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment report — {e(r.scope_name)}</title>
<style>
:root {{ color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --ink:#1a1d21; --muted:#6b7480; --line:#e3e6ea; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171a; --card:#1d2125; --ink:#e8eaed; --muted:#9aa4af; --line:#2a2f35; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif; }}
.wrap {{ max-width:960px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ font-size:22px; margin:0 0 4px; }}
h2 {{ font-size:17px; margin:28px 0 10px; border-bottom:1px solid var(--line); padding-bottom:6px; }}
h3 {{ font-size:14px; margin:18px 0 6px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 18px; }}
.meta div {{ margin:2px 0; }} .label {{ color:var(--muted); display:inline-block; min-width:120px; }}
.chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:12px 0; }}
.chip {{ color:#fff; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600; }}
.finding {{ background:var(--card); border:1px solid var(--line); border-left-width:4px; border-radius:8px; margin:10px 0; padding:12px 14px; }}
.sev-critical {{ border-left-color:{_SEV_COLOR['critical']}; }} .sev-high {{ border-left-color:{_SEV_COLOR['high']}; }}
.sev-medium {{ border-left-color:{_SEV_COLOR['medium']}; }} .sev-low {{ border-left-color:{_SEV_COLOR['low']}; }}
.sev-info {{ border-left-color:{_SEV_COLOR['info']}; }}
.finding-head {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
.sev-badge {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px; }}
.vbadge {{ color:#fff; font-size:11px; font-weight:600; padding:2px 8px; border-radius:10px; }}
.finding-body div {{ margin:2px 0; font-size:13.5px; }}
code {{ background:rgba(127,127,127,.14); padding:1px 5px; border-radius:4px; font-size:12.5px; }}
table {{ width:100%; border-collapse:collapse; margin:4px 0 8px; }}
td {{ padding:5px 8px; border-bottom:1px solid var(--line); font-size:13px; vertical-align:top; }}
.muted {{ color:var(--muted); }} .s-ok {{ color:#2e7d32; }} .s-skip {{ color:#c77700; }} .s-err {{ color:#b4232a; }}
.banner {{ background:rgba(180,35,42,.08); border:1px solid rgba(180,35,42,.3); color:var(--ink); font-size:12.5px; border-radius:8px; padding:10px 14px; margin-top:16px; }}
</style></head>
<body><div class="wrap">
  <h1>Assessment report — {e(r.scope_name)}</h1>
  <p class="muted">Scan <code>{e(r.scan_id)}</code> · {e(r.status)} · {_ts(r.created_at)} → {_ts(r.finished_at)}</p>
  <div class="chips">{chips}</div>

  <h2>Authorization</h2>
  <div class="card meta">{auth_rows}</div>

  <h2>OWASP Top 10 (2021) coverage</h2>
  <div class="card"><table>
    <thead><tr><th>Cat</th><th>Category</th><th>Top severity</th><th>Status</th></tr></thead>
    <tbody>{owasp_rows}</tbody></table></div>

  <h2>Findings</h2>
  {finding_rows}

  {f'<h2>Exploit plans <span class="muted">(operator-in-the-loop)</span></h2>{plan_rows}' if r.exploit_plans else ''}

  <h2>Assets <span class="muted">({len(r.assets)})</span></h2>
  <div class="card">{asset_blocks or '<p class="muted">None.</p>'}</div>

  <h2>Tool runs</h2>
  <div class="card"><table><tbody>{stage_rows}</tbody></table></div>

  <div class="banner">Generated by the authorized assessment orchestrator. This report
  documents testing performed under the authorization recorded above. Do not use against
  systems you are not permitted to test.</div>
</div></body></html>"""
