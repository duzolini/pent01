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
