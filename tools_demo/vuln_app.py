"""A deliberately vulnerable test app for demonstrating the validators LOCALLY.

Bind to 127.0.0.1 only. This exists so the confirmation layer can be shown
proving real vulnerabilities against a target we own. Never expose it.
"""
from flask import Flask, request, Response, redirect

app = Flask(__name__)

PRODUCTS = {"1": "Widget", "2": "Gadget", "3": "Sprocket"}


@app.after_request
def strip_headers(resp):
    # Intentionally omit security headers (HSTS/CSP/etc.).
    return resp


@app.route("/")
def home():
    return "<h1>Shop</h1><p>welcome</p>"


@app.route("/search")
def search():
    # Reflected XSS: q echoed back unencoded.
    q = request.args.get("q", "")
    return f"<h1>Results for: {q}</h1>"


@app.route("/item")
def item():
    # Boolean-based SQLi simulation: the injected AND condition decides the page,
    # exactly like a vulnerable `SELECT ... WHERE id='<id>'`.
    raw = request.args.get("id", "1")
    base = raw.split("'")[0]
    cond_true = True
    if "'" in raw:
        # crude emulation of SQL boolean evaluation on the trailing AND '1'='X
        cond_true = "'1'='1" in raw or "1=1" in raw
    if base in PRODUCTS and cond_true:
        return f"<h1>{PRODUCTS[base]}</h1><p>in stock</p>"
    return "<h1>No product found</h1>"


@app.route("/download")
def download():
    # Path traversal / LFI: reads an arbitrary file off disk.
    name = request.args.get("file", "readme.txt")
    try:
        with open(name, "r", errors="replace") as fh:
            return Response(fh.read(), mimetype="text/plain")
    except OSError:
        return Response("not found", status=404)


@app.route("/go")
def go():
    # Open redirect: next is used unvalidated.
    return redirect(request.args.get("next", "/"), code=302)


@app.route("/.git/config")
def git_config():
    return Response("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                    "[remote \"origin\"]\n\turl = git@github.com:acme/shop.git\n",
                    mimetype="text/plain")


@app.route("/assets/")
def assets():
    return ("<html><head><title>Index of /assets</title></head><body>"
            "<h1>Index of /assets/</h1><pre>app.js\nstyle.css\nbackup.zip</pre></body></html>")


@app.route("/api")
def api():
    # CORS misconfiguration: reflects any Origin and allows credentials.
    resp = Response('{"ok":true}', mimetype="application/json")
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/ssrf-canary")
def ssrf_canary():
    return "ssrf0canary0marker"


@app.route("/fetch-blind")
def fetch_blind():
    # BLIND SSRF: fetches the attacker URL server-side but returns nothing
    # useful — only an out-of-band listener can confirm it.
    import urllib.request
    url = request.args.get("url", "")
    try:
        urllib.request.urlopen(url, timeout=5).read(100)
    except Exception:  # noqa: BLE001
        pass
    return Response("queued", mimetype="text/plain")


@app.route("/fetch")
def fetch():
    # SSRF: fetches an attacker-supplied URL server-side and returns the body.
    import urllib.request
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return Response(r.read(2000), mimetype="text/plain")
    except Exception as exc:  # noqa: BLE001
        return Response(f"fetch error: {exc}", status=502)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, threaded=True)
