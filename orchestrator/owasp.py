"""Map findings to the OWASP Top 10 (2021) and summarise coverage.

Each validator declares the OWASP category it confirms (``Validator.owasp``);
findings without a validator are categorised by keyword. ``coverage()`` then
produces a per-category rollup for the report and dashboard: how many findings
fell in each category and how many were confirmed.
"""

from __future__ import annotations

from .models import Finding, Severity

CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Which OWASP category each validator confirms.
VALIDATOR_OWASP: dict[str, str] = {
    "git-exposed": "A05", "dir-listing": "A05", "header-recheck": "A05",
    "cors-misconfig": "A05",
    "open-redirect": "A01", "lfi": "A01", "access-control": "A01",
    "reflected-xss": "A03", "blind-xss": "A03", "sqli-boolean": "A03",
    "command-injection": "A03", "ssti": "A03", "nosql-injection": "A03",
    "tls-check": "A02", "jwt-weakness": "A02",
    "xxe": "A05", "graphql": "A05", "subdomain-takeover": "A05",
    "ssrf": "A10",
}

# Keyword fallback for findings a validator did not tag.
_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    (("sql", "xss", "injection", "lfi", "command inject", "traversal"), "A03"),
    (("ssrf", "server-side request"), "A10"),
    (("cors", ".git", "directory listing", "security header", "misconfig"), "A05"),
    (("tls", "ssl", "certificate", "hsts", "jwt", "crypto"), "A02"),
    (("cve-", "outdated", "version disclosed", "end of life", "eol"), "A06"),
    (("credential", "default cred", "password", "login", "ssh", "brute"), "A07"),
    (("deserial", "integrity", "unsigned", "supply chain"), "A08"),
    (("access control", "idor", "forced brows", "unauthenticated", "redirect"), "A01"),
    (("logging", "monitoring", "audit"), "A09"),
]


def categorize(f: Finding) -> str:
    """Return the OWASP category id for a finding, or '' if unknown."""
    tagged = (f.metadata or {}).get("owasp")
    if tagged in CATEGORIES:
        return tagged
    text = f"{f.title} {f.description}".lower()
    for keys, cat in _KEYWORDS:
        if any(k in text for k in keys):
            return cat
    return ""


def coverage(result) -> list[dict]:
    """Per-category rollup across all ten categories, highest severity first."""
    buckets: dict[str, list[Finding]] = {cid: [] for cid in CATEGORIES}
    for f in result.findings:
        cid = categorize(f)
        if cid:
            buckets[cid].append(f)
    rows = []
    for cid, title in CATEGORIES.items():
        items = buckets[cid]
        confirmed = sum(1 for f in items
                        if f.validation and f.validation.status == "confirmed")
        top = max((f.severity for f in items), key=lambda s: s.rank, default=Severity.INFO)
        rows.append({
            "id": cid, "title": title, "count": len(items),
            "confirmed": confirmed,
            "top_severity": top.value if items else "",
            "findings": sorted(items, key=lambda f: f.severity.rank, reverse=True),
        })
    return rows
