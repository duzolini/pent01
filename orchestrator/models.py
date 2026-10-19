"""Data models for assets, findings, and scan results."""

from __future__ import annotations

import dataclasses
import enum
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order[self.value]

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO


@dataclass
class Asset:
    """Something discovered in scope: a host, service, or URL."""

    kind: str  # "subdomain" | "host" | "service" | "url"
    value: str
    source: str = ""  # which tool found it
    metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    """A single observation worth a human's attention."""

    title: str
    severity: Severity
    target: str
    tool: str
    description: str = ""
    evidence: str = ""
    reference: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["severity"] = Severity.coerce(d.get("severity"))
        return cls(**d)


@dataclass
class StageResult:
    """Outcome of one pipeline stage (one tool run)."""

    stage: str
    tool: str
    status: str = "pending"  # pending|running|ok|skipped|error
    skipped_reason: str = ""
    started_at: float | None = None
    finished_at: float | None = None
    command: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "StageResult":
        return cls(**d)


@dataclass
class ScanResult:
    """Everything produced by one orchestration run."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    scope_name: str = ""
    targets: list[str] = field(default_factory=list)
    status: str = "pending"  # pending|running|done|error|aborted
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)
    authorization: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    # --- mutation helpers (de-duplicated) ---
    def add_asset(self, asset: Asset) -> None:
        if not any(a.key() == asset.key() for a in self.assets):
            self.assets.append(asset)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def assets_of(self, kind: str) -> list[Asset]:
        return [a for a in self.assets if a.kind == kind]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    # --- serialization ---
    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scope_name": self.scope_name,
            "targets": self.targets,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.findings],
            "stages": [s.to_dict() for s in self.stages],
            "authorization": self.authorization,
            "error": self.error,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        return cls(
            scan_id=d.get("scan_id", ""),
            scope_name=d.get("scope_name", ""),
            targets=d.get("targets", []),
            status=d.get("status", "pending"),
            created_at=d.get("created_at", time.time()),
            finished_at=d.get("finished_at"),
            assets=[Asset(**a) for a in d.get("assets", [])],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            stages=[StageResult.from_dict(s) for s in d.get("stages", [])],
            authorization=d.get("authorization", {}),
            error=d.get("error", ""),
        )
