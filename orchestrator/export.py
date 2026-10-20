"""Export findings for other tools and pipelines.

Formats:
  * SARIF 2.1.0  — ingested by GitHub code scanning and many SAST/DAST tools
  * findings JSON — flat, easy to post to an API or load elsewhere
  * CSV           — spreadsheets / quick triage
  * DefectDojo    — the "Generic Findings Import" JSON shape

Each finding also gets an indicative CVSS base score (derived from severity, or
``metadata.cvss`` when supplied) and a representative reproduction command.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from . import owasp
from .models import Finding, ScanResult, Severity

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}
_DD_SEV = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info"}
_CVSS_BY_SEV = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.1, "info": 0.0}


def cvss_base(f: Finding) -> float:
    """Indicative CVSS base score. Uses metadata.cvss if present, else severity."""
    try:
        return float(f.metadata.get("cvss"))
    except (TypeError, ValueError):
        return _CVSS_BY_SEV[f.severity.value]


def poc_curl(f: Finding) -> str:
    """A representative reproduction command for the finding."""
    param = f.metadata.get("param")
    if f.tool in ("xxe",) or "xxe" in f.title.lower():
        return (f"curl -s -X POST -H 'Content-Type: application/xml' "
                f"--data '<?xml ...><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                f"<r>&x;</r>' '{f.target}'")
    if "graphql" in f.title.lower():
        return f"curl -s -X POST -H 'Content-Type: application/json' --data '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' '{f.target}'"
    note = f"   # inject into '{param}'" if param else ""
    return f"curl -s '{f.target}'{note}"


def _finding_dict(f: Finding) -> dict:
    cat = owasp.categorize(f)
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "cvss": cvss_base(f),
        "target": f.target,
        "tool": f.tool,
        "description": f.description,
        "owasp": cat,
        "owasp_title": owasp.CATEGORIES.get(cat, ""),
        "validation": f.validation.status if f.validation else "unverified",
        "evidence": (f.validation.evidence if f.validation else "") or f.evidence,
        "reference": f.reference,
        "poc": poc_curl(f),
    }


# ---------------------------------------------------------------------- #
def to_findings_json(result: ScanResult) -> str:
    payload = {
        "scan_id": result.scan_id,
        "scope": result.scope_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        "authorization": result.authorization,
        "findings": [_finding_dict(f) for f in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2)


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    cols = ["severity", "cvss", "owasp", "title", "target", "validation", "tool",
            "evidence", "reference"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for f in result.sorted_findings():
        w.writerow(_finding_dict(f))
    return buf.getvalue()


def to_sarif(result: ScanResult) -> str:
    rules, rule_index = [], {}
    results = []
    for f in result.sorted_findings():
        cat = owasp.categorize(f) or "GEN"
        if cat not in rule_index:
            rule_index[cat] = len(rules)
            rules.append({
                "id": cat,
                "name": owasp.CATEGORIES.get(cat, "General"),
                "shortDescription": {"text": owasp.CATEGORIES.get(cat, "General finding")},
                "properties": {"category": "OWASP Top 10 2021"},
            })
        results.append({
            "ruleId": cat,
            "ruleIndex": rule_index[cat],
            "level": _SARIF_LEVEL[f.severity.value],
            "message": {"text": f"{f.title}. {f.description}".strip()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.target}}}],
            "properties": {
                "severity": f.severity.value,
                "cvss": cvss_base(f),
                "validation": f.validation.status if f.validation else "unverified",
                "evidence": (f.validation.evidence if f.validation else "") or f.evidence,
                "poc": poc_curl(f),
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "assessment-orchestrator",
                "informationUri": "https://github.com/duzolini/pent01",
                "version": "0.1.0",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_defectdojo(result: ScanResult) -> str:
    """DefectDojo 'Generic Findings Import' JSON."""
    findings = []
    for f in result.sorted_findings():
        d = _finding_dict(f)
        findings.append({
            "title": f.title,
            "severity": _DD_SEV[f.severity.value],
            "description": f.description or f.title,
            "mitigation": "",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "cvssv3_score": d["cvss"],
            "endpoints": [f.target],
            "references": f.reference,
            "unique_id_from_tool": f.id,
            "vuln_id_from_tool": d["owasp"],
            "dynamic_finding": True,
            "active": True,
            "verified": d["validation"] == "confirmed",
            "steps_to_reproduce": d["poc"],
        })
    return json.dumps({"findings": findings}, indent=2)


FORMATS = {
    "sarif": (to_sarif, "sarif.json"),
    "json": (to_findings_json, "findings.json"),
    "csv": (to_csv, "findings.csv"),
    "defectdojo": (to_defectdojo, "defectdojo.json"),
}


def export(result: ScanResult, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    return FORMATS[fmt][0](result)
