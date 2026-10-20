"""Persistence for scan results — flat JSON files under ``data/scans``."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "scans"


def _dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def save(result: ScanResult) -> Path:
    path = _dir() / f"{result.scan_id}.json"
    path.write_text(result.to_json())
    return path


def load(scan_id: str) -> ScanResult | None:
    path = _dir() / f"{scan_id}.json"
    if not path.exists():
        return None
    return ScanResult.from_dict(json.loads(path.read_text()))


def list_scans() -> list[ScanResult]:
    scans = []
    for path in _dir().glob("*.json"):
        try:
            scans.append(ScanResult.from_dict(json.loads(path.read_text())))
        except (json.JSONDecodeError, KeyError):
            continue
    return sorted(scans, key=lambda s: s.created_at, reverse=True)


def scans_for_scope(scope_name: str) -> list[ScanResult]:
    """All scans for a scope, newest first."""
    return [s for s in list_scans() if s.scope_name == scope_name]


def previous_scan(result: ScanResult) -> ScanResult | None:
    """The most recent completed scan of the same scope before ``result``."""
    prior = [s for s in scans_for_scope(result.scope_name)
             if s.scan_id != result.scan_id and s.created_at < result.created_at]
    return prior[0] if prior else None
