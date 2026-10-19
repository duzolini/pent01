"""Scope loading and the authorization gate.

Nothing in this project touches a target that is not explicitly allowed by a
scope file, and no scan runs unless the scope is marked ``authorized: true``.
This module is the single choke point that enforces both rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")


class ScopeError(Exception):
    """Raised when a scope is invalid or a target is out of scope."""


@dataclass
class Scope:
    name: str
    authorized: bool = False
    # Authorization provenance — recorded into every scan for the audit trail.
    client: str = ""
    authorized_by: str = ""
    authorization_ref: str = ""  # contract / ticket / bug-bounty program URL
    expires: str = ""  # ISO date; informational
    # Allow-list.
    domains: list[str] = field(default_factory=list)  # apex or exact FQDNs
    hosts: list[str] = field(default_factory=list)  # individual IPs / FQDNs
    cidrs: list[str] = field(default_factory=list)  # CIDR ranges
    # Explicit exclusions win over everything else.
    exclude: list[str] = field(default_factory=list)
    # Safety knobs (consumed by the runner / tool wrappers).
    rate_limit: int = 50  # max requests/sec hint passed to tools
    max_concurrency: int = 10
    intrusive: bool = False  # gate for anything beyond passive/safe checks
    validate: bool = True  # run safe non-destructive confirmation of findings

    _networks: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)
    _exclude_networks: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        # Validate first so an invalid scope raises ScopeError (not ValueError)
        # regardless of whether it was built via load() or constructed directly.
        self._check_valid()
        self._networks = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
        self._exclude_networks = []
        for item in self.exclude:
            try:
                self._exclude_networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass  # non-CIDR exclusions handled as string/domain matches

    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"scope file not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}
        if not isinstance(data, dict):
            raise ScopeError("scope file must be a YAML mapping")
        known = {
            "name", "authorized", "client", "authorized_by", "authorization_ref",
            "expires", "domains", "hosts", "cidrs", "exclude", "rate_limit",
            "max_concurrency", "intrusive", "validate",
        }
        unknown = set(data) - known
        if unknown:
            raise ScopeError(f"unknown scope keys: {', '.join(sorted(unknown))}")
        scope = cls(
            name=str(data.get("name") or path.stem),
            authorized=bool(data.get("authorized", False)),
            client=str(data.get("client", "")),
            authorized_by=str(data.get("authorized_by", "")),
            authorization_ref=str(data.get("authorization_ref", "")),
            expires=str(data.get("expires", "")),
            domains=[d.strip().lower() for d in data.get("domains", []) if str(d).strip()],
            hosts=[h.strip().lower() for h in data.get("hosts", []) if str(h).strip()],
            cidrs=[str(c).strip() for c in data.get("cidrs", []) if str(c).strip()],
            exclude=[str(e).strip().lower() for e in data.get("exclude", []) if str(e).strip()],
            rate_limit=int(data.get("rate_limit", 50)),
            max_concurrency=int(data.get("max_concurrency", 10)),
            intrusive=bool(data.get("intrusive", False)),
            validate=bool(data.get("validate", True)),
        )
        scope._check_valid()
        return scope

    def _check_valid(self) -> None:
        if not self.name:
            raise ScopeError("scope.name is required")
        if not (self.domains or self.hosts or self.cidrs):
            raise ScopeError("scope must declare at least one of: domains, hosts, cidrs")
        for d in self.domains + self.hosts:
            if not (_DOMAIN_RE.match(d) or _is_ip(d)):
                raise ScopeError(f"invalid domain/host entry: {d!r}")
        for c in self.cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError as exc:
                raise ScopeError(f"invalid CIDR {c!r}: {exc}") from exc

    # ------------------------------------------------------------------ #
    def require_authorized(self) -> None:
        """The hard gate. Raises unless the scope is explicitly authorized."""
        if not self.authorized:
            raise ScopeError(
                f"scope {self.name!r} is not authorized. Set 'authorized: true' in the "
                "scope file only when you hold written permission to test these targets."
            )

    def is_in_scope(self, target: str) -> bool:
        """True iff ``target`` (host, FQDN, IP, or URL) is covered and not excluded."""
        host = _extract_host(target)
        if not host:
            return False
        host = host.lower()

        # Exclusions win.
        if host in self.exclude:
            return False
        ip = _as_ip(host)
        if ip is not None:
            for net in self._exclude_networks:
                if ip in net:
                    return False

        # Explicit host / IP match.
        if host in self.hosts or host in self.domains:
            return True
        # Subdomain of an allowed apex domain.
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        # CIDR membership.
        if ip is not None:
            for net in self._networks:
                if ip in net:
                    return True
        return False

    def assert_in_scope(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise ScopeError(f"refusing out-of-scope target: {target!r}")

    def seed_targets(self) -> list[str]:
        """Initial targets to feed the pipeline."""
        return list(dict.fromkeys(self.domains + self.hosts + self.cidrs))

    def authorization_record(self) -> dict[str, Any]:
        return {
            "scope": self.name,
            "client": self.client,
            "authorized_by": self.authorized_by,
            "authorization_ref": self.authorization_ref,
            "expires": self.expires,
            "authorized": self.authorized,
        }


# ---------------------------------------------------------------------- #
def _is_ip(value: str) -> bool:
    return _as_ip(value) is not None


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _extract_host(target: str) -> str:
    """Pull a bare host out of a URL / host:port / plain host."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("@")[-1]  # strip creds if present
    # Strip :port but preserve bracketed IPv6.
    if t.startswith("["):
        return t[1 : t.index("]")] if "]" in t else t
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t
