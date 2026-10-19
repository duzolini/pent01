"""Wrappers around external scanning tools, plus a couple of native checks.

Each wrapper:
  * knows which binary it needs and reports whether it is installed,
  * builds a non-destructive command (safe defaults, rate limited),
  * runs it with a timeout under scope enforcement,
  * parses output into Assets / Findings.

Every wrapper degrades gracefully: if its binary is missing it marks the stage
``skipped`` instead of failing the run. The two native checks (security headers,
TLS) are pure-Python and always available.
"""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Iterable

from .models import Asset, Finding, Severity
from .scope import Scope


class ToolResult:
    def __init__(self) -> None:
        self.assets: list[Asset] = []
        self.findings: list[Finding] = []
        self.command: str = ""

    def extend(self, other: "ToolResult") -> None:
        self.assets.extend(other.assets)
        self.findings.extend(other.findings)


class Tool:
    """Base class for a pipeline tool."""

    name: str = "tool"
    binary: str | None = None  # external binary, or None for native checks
    stage: str = "misc"

    def __init__(self, scope: Scope, timeout: int = 600) -> None:
        self.scope = scope
        self.timeout = timeout

    def available(self) -> bool:
        if self.binary is None:
            return True
        return shutil.which(self.binary) is not None

    def run(self, targets: list[str]) -> ToolResult:  # pragma: no cover - overridden
        raise NotImplementedError

    # -- helpers --
    def _exec(self, cmd: list[str], input_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )

    @staticmethod
    def _iter_jsonl(text: str) -> Iterable[dict]:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ====================================================================== #
# Recon
# ====================================================================== #
class Subfinder(Tool):
    name = "subfinder"
    binary = "subfinder"
    stage = "recon"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        domains = [t for t in targets if not _looks_like_ip(t) and "/" not in t]
        for domain in domains:
            cmd = ["subfinder", "-d", domain, "-silent", "-oJ"]
            res.command = " ".join(cmd)
            proc = self._exec(cmd)
            for obj in self._iter_jsonl(proc.stdout):
                host = obj.get("host") or obj.get("input")
                if host and self.scope.is_in_scope(host):
                    res.assets.append(Asset("subdomain", host.lower(), source=self.name))
        return res


class Dnsx(Tool):
    name = "dnsx"
    binary = "dnsx"
    stage = "recon"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        hosts = [t for t in targets if "/" not in t]
        if not hosts:
            return res
        cmd = ["dnsx", "-silent", "-json", "-a", "-resp"]
        res.command = " ".join(cmd)
        proc = self._exec(cmd, input_text="\n".join(hosts))
        for obj in self._iter_jsonl(proc.stdout):
            host = obj.get("host")
            if not host or not self.scope.is_in_scope(host):
                continue
            a = Asset("host", host.lower(), source=self.name,
                      metadata={"a": obj.get("a", [])})
            res.assets.append(a)
        return res


class Httpx(Tool):
    name = "httpx"
    binary = "httpx"
    stage = "recon"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        hosts = [t for t in targets if "/" not in t]
        if not hosts:
            return res
        cmd = ["httpx", "-silent", "-json", "-title", "-status-code",
               "-tech-detect", "-web-server", "-rl", str(self.scope.rate_limit)]
        res.command = " ".join(cmd)
        proc = self._exec(cmd, input_text="\n".join(hosts))
        for obj in self._iter_jsonl(proc.stdout):
            url = obj.get("url")
            if not url or not self.scope.is_in_scope(url):
                continue
            res.assets.append(Asset(
                "url", url, source=self.name,
                metadata={
                    "status_code": obj.get("status_code"),
                    "title": obj.get("title"),
                    "webserver": obj.get("webserver"),
                    "tech": obj.get("tech") or obj.get("technologies"),
                },
            ))
        return res


# ====================================================================== #
# Port / service scanning
# ====================================================================== #
class Naabu(Tool):
    name = "naabu"
    binary = "naabu"
    stage = "ports"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        hosts = [t for t in targets if "/" not in t and not t.startswith("http")]
        if not hosts:
            return res
        cmd = ["naabu", "-silent", "-json", "-rate", str(self.scope.rate_limit),
               "-top-ports", "1000"]
        res.command = " ".join(cmd)
        proc = self._exec(cmd, input_text="\n".join(hosts))
        for obj in self._iter_jsonl(proc.stdout):
            host, port = obj.get("host") or obj.get("ip"), obj.get("port")
            if not host or not self.scope.is_in_scope(host):
                continue
            res.assets.append(Asset(
                "service", f"{host}:{port}", source=self.name,
                metadata={"host": host, "port": port},
            ))
        return res


class Nmap(Tool):
    name = "nmap"
    binary = "nmap"
    stage = "ports"

    def run(self, targets: list[str]) -> ToolResult:
        import xml.etree.ElementTree as ET

        res = ToolResult()
        hosts = [t for t in targets if not t.startswith("http")]
        if not hosts:
            return res
        # -sV service/version detection, -T3 polite timing, no aggressive scripts.
        cmd = ["nmap", "-sV", "-Pn", "-T3", "--open", "-oX", "-", *hosts]
        res.command = " ".join(cmd)
        proc = self._exec(cmd)
        if not proc.stdout.strip():
            return res
        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError:
            return res
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host = addr_el.get("addr") if addr_el is not None else None
            if not host or not self.scope.is_in_scope(host):
                continue
            for port_el in host_el.findall("./ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port_el.get("portid")
                svc = port_el.find("service")
                svc_name = svc.get("name") if svc is not None else ""
                product = " ".join(filter(None, [
                    svc.get("product") if svc is not None else "",
                    svc.get("version") if svc is not None else "",
                ])).strip()
                res.assets.append(Asset(
                    "service", f"{host}:{portid}", source=self.name,
                    metadata={"host": host, "port": portid,
                              "service": svc_name, "product": product},
                ))
        return res


# ====================================================================== #
# Web vulnerability scanning
# ====================================================================== #
class Nuclei(Tool):
    name = "nuclei"
    binary = "nuclei"
    stage = "web"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        urls = [t for t in targets if t.startswith("http")]
        if not urls:
            return res
        cmd = ["nuclei", "-jsonl", "-silent", "-rl", str(self.scope.rate_limit),
               "-c", str(self.scope.max_concurrency)]
        # Non-destructive by default: exclude intrusive/fuzzing/dos templates
        # unless the scope explicitly opts in to intrusive testing.
        if not self.scope.intrusive:
            cmd += ["-etags", "fuzz,dos,intrusive,brute-force"]
        res.command = " ".join(cmd)
        proc = self._exec(cmd, input_text="\n".join(urls))
        for obj in self._iter_jsonl(proc.stdout):
            info = obj.get("info", {})
            res.findings.append(Finding(
                title=info.get("name") or obj.get("template-id", "nuclei finding"),
                severity=Severity.coerce(info.get("severity")),
                target=obj.get("matched-at") or obj.get("host", ""),
                tool=self.name,
                description=info.get("description", ""),
                evidence=obj.get("matched-at", ""),
                reference=(info.get("reference") or [""])[0]
                if isinstance(info.get("reference"), list) else info.get("reference", ""),
                metadata={"template": obj.get("template-id"),
                          "tags": info.get("tags")},
            ))
        return res


class Nikto(Tool):
    name = "nikto"
    binary = "nikto"
    stage = "web"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        urls = [t for t in targets if t.startswith("http")]
        for url in urls:
            cmd = ["nikto", "-h", url, "-Format", "json", "-output", "-", "-nointeractive"]
            res.command = " ".join(cmd)
            proc = self._exec(cmd)
            try:
                data = json.loads(proc.stdout)
            except (json.JSONDecodeError, ValueError):
                continue
            vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
            for v in vulns:
                res.findings.append(Finding(
                    title=v.get("msg", "nikto finding")[:120],
                    severity=Severity.LOW,
                    target=url,
                    tool=self.name,
                    description=v.get("msg", ""),
                    reference=v.get("references", ""),
                    metadata={"id": v.get("id"), "method": v.get("method")},
                ))
        return res


# ====================================================================== #
# Native checks (always available — no external binary)
# ====================================================================== #
_SECURITY_HEADERS = {
    "strict-transport-security": Severity.MEDIUM,
    "content-security-policy": Severity.LOW,
    "x-frame-options": Severity.LOW,
    "x-content-type-options": Severity.LOW,
    "referrer-policy": Severity.INFO,
    "permissions-policy": Severity.INFO,
}


class HttpHeaders(Tool):
    name = "http-headers"
    binary = None
    stage = "web"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        res.command = "native: HTTP security-header inspection"
        for url in [t for t in targets if t.startswith("http")]:
            try:
                req = urllib.request.Request(url, method="HEAD",
                                             headers={"User-Agent": "assessment-orchestrator"})
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            except Exception:  # noqa: BLE001 - network errors are expected/benign here
                continue
            missing = [h for h in _SECURITY_HEADERS if h not in headers]
            for h in missing:
                res.findings.append(Finding(
                    title=f"Missing security header: {h}",
                    severity=_SECURITY_HEADERS[h],
                    target=url,
                    tool=self.name,
                    description=f"Response from {url} does not set the '{h}' header.",
                    reference="https://owasp.org/www-project-secure-headers/",
                ))
            if "server" in headers and _version_in(headers["server"]):
                res.findings.append(Finding(
                    title="Server version disclosed",
                    severity=Severity.LOW,
                    target=url,
                    tool=self.name,
                    description=f"Server header reveals software/version: {headers['server']}",
                    evidence=headers["server"],
                ))
        return res


class TlsCheck(Tool):
    name = "tls-check"
    binary = None
    stage = "web"

    def run(self, targets: list[str]) -> ToolResult:
        res = ToolResult()
        res.command = "native: TLS certificate inspection"
        seen: set[tuple[str, int]] = set()
        for t in targets:
            host, port = _host_port_for_tls(t)
            if host is None or (host, port) in seen:
                continue
            seen.add((host, port))
            if not self.scope.is_in_scope(host):
                continue
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=15) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        version = ssock.version()
            except Exception:  # noqa: BLE001
                continue
            if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                res.findings.append(Finding(
                    title=f"Deprecated TLS version supported: {version}",
                    severity=Severity.MEDIUM, target=f"{host}:{port}", tool=self.name,
                    description=f"Server negotiated {version}, which is deprecated.",
                ))
            not_after = cert.get("notAfter") if cert else None
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if days < 0:
                        sev, msg = Severity.HIGH, f"Certificate expired {-days} days ago."
                    elif days < 21:
                        sev, msg = Severity.MEDIUM, f"Certificate expires in {days} days."
                    else:
                        sev, msg = None, ""
                    if sev:
                        res.findings.append(Finding(
                            title="TLS certificate expiry", severity=sev,
                            target=f"{host}:{port}", tool=self.name, description=msg,
                            evidence=f"notAfter={not_after}"))
                except ValueError:
                    pass
        return res


# ---------------------------------------------------------------------- #
# Registry — ordered pipeline.
ALL_TOOLS: list[type[Tool]] = [
    Subfinder, Dnsx, Httpx,          # recon
    Naabu, Nmap,                     # ports
    Nuclei, Nikto, HttpHeaders, TlsCheck,  # web
]


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _version_in(text: str) -> bool:
    return any(ch.isdigit() for ch in text)


def _host_port_for_tls(target: str) -> tuple[str | None, int]:
    t = target.strip()
    if t.startswith("https://"):
        rest = t[len("https://"):].split("/", 1)[0]
        if ":" in rest and not rest.startswith("["):
            h, p = rest.rsplit(":", 1)
            return h, int(p) if p.isdigit() else 443
        return rest, 443
    if t.startswith("http://"):
        return None, 0  # plaintext; nothing to inspect
    if "/" in t:
        return None, 0
    return t, 443
