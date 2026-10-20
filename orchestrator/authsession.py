"""Authenticated scanning: build request headers from a scope's ``auth`` block.

Many findings only appear behind a login (broken access control, IDOR, stored
XSS). This turns a scope's declared credentials into headers that validators
attach to every request. Supported ``auth.type``:

    basic   : {type: basic, username: u, password: p}
    bearer  : {type: bearer, token: "..."}
    header  : {type: header, headers: {X-API-Key: "..."}}
    cookie  : {type: cookie, cookie: "session=abc; other=1"}
    form    : {type: form, login_url: "...", data: {user: u, pass: p},
               success: "optional substring that proves login worked"}

Credentials live only in the scope file the operator controls.
"""

from __future__ import annotations

import base64
import urllib.parse
import urllib.request


class AuthError(Exception):
    pass


def build_headers(auth: dict, timeout: int = 10) -> dict[str, str]:
    """Return headers that authenticate a request, performing form login if needed."""
    if not auth:
        return {}
    kind = str(auth.get("type", "")).lower()

    if kind == "basic":
        raw = f"{auth.get('username', '')}:{auth.get('password', '')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    if kind == "bearer":
        return {"Authorization": f"Bearer {auth.get('token', '')}"}

    if kind == "header":
        return {str(k): str(v) for k, v in (auth.get("headers") or {}).items()}

    if kind == "cookie":
        return {"Cookie": str(auth.get("cookie", ""))}

    if kind == "form":
        return _form_login(auth, timeout)

    raise AuthError(f"unknown auth.type: {kind!r}")


def _form_login(auth: dict, timeout: int) -> dict[str, str]:
    import http.cookiejar
    login_url = auth.get("login_url")
    if not login_url:
        raise AuthError("form auth requires login_url")
    data = urllib.parse.urlencode(auth.get("data") or {}).encode()
    req = urllib.request.Request(login_url, data=data, method="POST",
                                 headers={"User-Agent": "assessment-orchestrator",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(50000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(50000).decode("utf-8", "replace") if e.fp else ""

    success = auth.get("success")
    if success and success not in body:
        raise AuthError("form login did not show the success marker")
    cookies = [f"{c.name}={c.value}" for c in jar]
    if not cookies:
        raise AuthError("form login returned no Set-Cookie")
    return {"Cookie": "; ".join(cookies)}
