"""Compare two scans — the basis of continuous assessment.

Surfaces what changed between runs of the same scope: findings that are NEW,
findings that were RESOLVED (present before, gone now), and newly discovered
assets. A finding is identified by (title, target) so re-running a scope lines
findings up across runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Asset, Finding, ScanResult


def finding_key(f: Finding) -> tuple[str, str]:
    return (f.title.strip().lower(), f.target.strip().lower())


@dataclass
class ScanDiff:
    old_id: str
    new_id: str
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)
    new_assets: list[Asset] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new_findings or self.resolved_findings or self.new_assets)

    def summary(self) -> str:
        return (f"+{len(self.new_findings)} new, -{len(self.resolved_findings)} resolved, "
                f"{len(self.unchanged_findings)} unchanged, +{len(self.new_assets)} new assets")


def diff_scans(old: ScanResult, new: ScanResult) -> ScanDiff:
    old_map = {finding_key(f): f for f in old.findings}
    new_map = {finding_key(f): f for f in new.findings}
    d = ScanDiff(old_id=old.scan_id, new_id=new.scan_id)
    for k, f in new_map.items():
        (d.unchanged_findings if k in old_map else d.new_findings).append(f)
    for k, f in old_map.items():
        if k not in new_map:
            d.resolved_findings.append(f)
    old_assets = {(a.kind, a.value) for a in old.assets}
    d.new_assets = [a for a in new.assets if (a.kind, a.value) not in old_assets]
    d.new_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return d


def render(d: ScanDiff) -> str:
    lines = [f"Diff {d.old_id} → {d.new_id}", d.summary(), ""]
    if d.new_findings:
        lines.append("NEW findings:")
        for f in d.new_findings:
            v = f" [{f.validation.status}]" if f.validation else ""
            lines.append(f"  + [{f.severity.value.upper()}] {f.title} ({f.target}){v}")
    if d.resolved_findings:
        lines.append("RESOLVED findings:")
        for f in d.resolved_findings:
            lines.append(f"  - [{f.severity.value.upper()}] {f.title} ({f.target})")
    if d.new_assets:
        lines.append("NEW assets:")
        for a in d.new_assets:
            lines.append(f"  + {a.kind}: {a.value}")
    if not d.changed:
        lines.append("No changes since the previous scan.")
    return "\n".join(lines)
