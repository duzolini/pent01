"""The orchestration pipeline.

Runs tools stage by stage. Assets discovered in one stage feed the next:
recon finds hosts/URLs, the port stage expands services, the web stage scans
the live URLs. Every target is re-checked against the scope before a tool
touches it, and the whole run refuses to start unless the scope is authorized.
"""

from __future__ import annotations

import time
from typing import Callable

from . import store
from .models import ScanResult, StageResult
from .scope import Scope
from .tools import ALL_TOOLS, Tool

STAGES = ["recon", "ports", "web"]

ProgressCb = Callable[[ScanResult], None]


class Runner:
    def __init__(self, scope: Scope, tool_timeout: int = 900) -> None:
        self.scope = scope
        self.tool_timeout = tool_timeout

    def run(self, on_progress: ProgressCb | None = None) -> ScanResult:
        # --- the gate ---
        self.scope.require_authorized()

        result = ScanResult(
            scope_name=self.scope.name,
            targets=self.scope.seed_targets(),
            status="running",
            authorization=self.scope.authorization_record(),
        )
        store.save(result)

        def tick() -> None:
            store.save(result)
            if on_progress:
                on_progress(result)

        # Seed the working set with scope targets.
        for t in self.scope.seed_targets():
            kind = "host" if "/" not in t else "service"
            result.add_asset(_seed_asset(t))

        try:
            for stage in STAGES:
                self._run_stage(stage, result, tick)
            self._validate_and_plan(result, tick)
            result.status = "done"
        except Exception as exc:  # noqa: BLE001 - surface any orchestration failure
            result.status = "error"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.finished_at = time.time()
            tick()
        return result

    # ------------------------------------------------------------------ #
    def _run_stage(self, stage: str, result: ScanResult, tick: ProgressCb) -> None:
        targets = self._targets_for(stage, result)
        for tool_cls in [t for t in ALL_TOOLS if t.stage == stage]:
            tool = tool_cls(self.scope, timeout=self.tool_timeout)
            sr = StageResult(stage=stage, tool=tool.name, status="running",
                             started_at=time.time())
            result.stages.append(sr)
            tick()

            if not tool.available():
                sr.status = "skipped"
                sr.skipped_reason = f"'{tool.binary}' not found in PATH"
                sr.finished_at = time.time()
                tick()
                continue

            # Final scope guard: only hand the tool in-scope targets.
            safe_targets = [t for t in targets if self.scope.is_in_scope(t)]
            if not safe_targets:
                sr.status = "skipped"
                sr.skipped_reason = "no in-scope targets for this stage"
                sr.finished_at = time.time()
                tick()
                continue

            try:
                out = tool.run(safe_targets)
                sr.command = out.command
                for a in out.assets:
                    if self.scope.is_in_scope(a.value):
                        result.add_asset(a)
                for f in out.findings:
                    result.add_finding(f)
                sr.status = "ok"
            except Exception as exc:  # noqa: BLE001
                sr.status = "error"
                sr.error = f"{type(exc).__name__}: {exc}"
            finally:
                sr.finished_at = time.time()
                tick()

    def _validate_and_plan(self, result: ScanResult, tick: ProgressCb) -> None:
        """Safe confirmation of findings, then propose operator-in-the-loop plans."""
        from . import exploit, validators

        sr = StageResult(stage="validate", tool="safe-validators", status="running",
                         started_at=time.time())
        result.stages.append(sr)
        tick()
        if not self.scope.validate:
            sr.status = "skipped"
            sr.skipped_reason = "validate: false in scope"
            sr.finished_at = time.time()
            tick()
        else:
            try:
                confirmed = validators.validate_findings(result, self.scope)
                sr.status = "ok"
                sr.command = f"confirmed {confirmed}/{len(result.findings)} findings"
            except Exception as exc:  # noqa: BLE001
                sr.status = "error"
                sr.error = f"{type(exc).__name__}: {exc}"
            sr.finished_at = time.time()
            tick()

        # Propose (never execute) exploitation steps for applicable findings.
        pr = StageResult(stage="plan", tool="exploit-planner", status="running",
                         started_at=time.time())
        result.stages.append(pr)
        tick()
        try:
            n = exploit.build_plans(result, self.scope)
            pr.status = "ok"
            pr.command = f"{n} exploit plan(s) proposed (operator-in-the-loop)"
        except Exception as exc:  # noqa: BLE001
            pr.status = "error"
            pr.error = f"{type(exc).__name__}: {exc}"
        pr.finished_at = time.time()
        tick()

    def _targets_for(self, stage: str, result: ScanResult) -> list[str]:
        if stage == "recon":
            return self.scope.seed_targets()
        if stage == "ports":
            hosts = {a.value for a in result.assets if a.kind in ("subdomain", "host")}
            hosts |= set(self.scope.seed_targets())
            return sorted(hosts)
        if stage == "web":
            urls = {a.value for a in result.assets if a.kind == "url"}
            # Augment with derived https:// candidates from discovered hosts and
            # seed domains, so native header/TLS checks and web scanners still
            # have targets even when httpx was unavailable to confirm live URLs.
            hostlike = {a.value for a in result.assets if a.kind in ("subdomain", "host")}
            hostlike |= {t for t in self.scope.seed_targets() if "/" not in t}
            for h in hostlike:
                urls.add(f"https://{h}")
            return sorted(urls)
        return []


def _seed_asset(target: str):
    from .models import Asset
    kind = "service" if "/" in target else "host"
    return Asset(kind, target, source="scope")
