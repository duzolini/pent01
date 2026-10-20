"""In-process scheduler for continuous assessment from the dashboard.

Runs a scope's pipeline on a repeating interval in a background thread, so the
operator can turn continuous monitoring on and off from the web UI without the
CLI. Each run is a normal ``Runner`` run (same authorization gate), persisted
like any other scan; the dashboard's diff panel then shows what changed.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .runner import Runner
from .scope import Scope


@dataclass
class Watcher:
    scope_name: str
    scope_path: str
    interval: int
    runs: int = 0
    last_run_id: str = ""
    last_run_at: float | None = None
    started_at: float = field(default_factory=time.time)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def status(self) -> dict:
        return {
            "scope_name": self.scope_name, "interval": self.interval,
            "runs": self.runs, "last_run_id": self.last_run_id,
            "last_run_at": self.last_run_at, "started_at": self.started_at,
            "alive": bool(self._thread and self._thread.is_alive()),
        }


class Scheduler:
    """Manages at most one watcher per scope."""

    def __init__(self) -> None:
        self._watchers: dict[str, Watcher] = {}
        self._lock = threading.Lock()

    def list(self) -> list[dict]:
        with self._lock:
            return [w.status() for w in self._watchers.values()]

    def is_watching(self, scope_name: str) -> bool:
        w = self._watchers.get(scope_name)
        return bool(w and w._thread and w._thread.is_alive())

    def start(self, scope: Scope, scope_path: str, interval: int) -> Watcher:
        scope.require_authorized()
        interval = max(60, int(interval))  # never hammer a target faster than 1/min
        with self._lock:
            if self.is_watching(scope.name):
                return self._watchers[scope.name]
            w = Watcher(scope_name=scope.name, scope_path=scope_path, interval=interval)
            t = threading.Thread(target=self._loop, args=(w, scope), daemon=True)
            w._thread = t
            self._watchers[scope.name] = w
            t.start()
            return w

    def stop(self, scope_name: str) -> bool:
        with self._lock:
            w = self._watchers.get(scope_name)
            if not w:
                return False
            w._stop.set()
            return True

    def _loop(self, w: Watcher, scope: Scope) -> None:
        while not w._stop.is_set():
            try:
                result = Runner(scope).run()
                w.runs += 1
                w.last_run_id = result.scan_id
                w.last_run_at = time.time()
            except Exception:  # noqa: BLE001 - keep the watcher alive across failures
                pass
            # Sleep in short slices so stop() is responsive.
            for _ in range(w.interval):
                if w._stop.is_set():
                    return
                time.sleep(1)
