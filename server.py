#!/usr/bin/env python3
"""OpenCert API — accept an OpenCert file and open it in a certificate viewer.

Endpoints:
  POST /api/certificates          upload an OpenCert (multipart file part or raw JSON)
  GET  /api/certificates          list stored certificates
  GET  /api/certificates/<id>     fetch a stored certificate as JSON
  GET  /view/<id>                 open the certificate in the built-in viewer
  GET  /                          API docs / landing page

Environment:
  PORT                  listen port (default 8080)
  HOST                  bind address (default 0.0.0.0)
  CERT_DATA_DIR         storage directory (default ./data/certificates)
  OPENCERT_VIEWER_URL   base URL of the OpenCert viewer (default
                        https://www.opencerts.io/). The returned viewerUrl is
                        this base with the hosted certificate URL appended.
                        A built-in viewer page is also served at /view/<id>.

Stdlib only — no third-party dependencies.
"""

import email.parser
import email.policy
import html
import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request
from urllib.parse import parse_qs, quote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8080"))
HOST = os.environ.get("HOST", "0.0.0.0")
DATA_DIR = os.environ.get("CERT_DATA_DIR", os.path.join(HERE, "data", "certificates"))
VIEWER_URL_PREFIX = os.environ.get(
    "OPENCERT_VIEWER_URL", "https://www.opencerts.io/").strip()
ID_RE = re.compile(r"^[a-f0-9]{16}$")
MAX_BODY = 5 * 1024 * 1024  # 5 MB


# ---------------------------------------------------------------- storage

def cert_path(cert_id):
    if not ID_RE.match(cert_id):
        return None
    return os.path.join(DATA_DIR, cert_id + ".json")


def save_certificate(doc):
    os.makedirs(DATA_DIR, exist_ok=True)
    cert_id = uuid.uuid4().hex[:16]
    with open(cert_path(cert_id), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return cert_id


def load_certificate(cert_id):
    path = cert_path(cert_id)
    if path is None or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_certificates():
    os.makedirs(DATA_DIR, exist_ok=True)
    out = []
    for name in sorted(os.listdir(DATA_DIR), reverse=True):
        if not (ID_RE.match(name[:-5]) and name.endswith(".json")):
            continue
        try:
            doc = load_certificate(name[:-5])
        except (json.JSONDecodeError, OSError):
            continue
        out.append({"id": name[:-5], "name": display_name(doc), "issued": issued_date(doc)})
    return out


# ------------------------------------------------------------- validation

ENCODED_FIELD_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"[:.](string|number|json)[:.](.*)$", re.S)


def decode_field(value):
    """OpenAttestation-style documents encode values as '<uuid>:<type>:<value>'.

    Return the human-readable part (or the value unchanged)."""
    if isinstance(value, str):
        m = ENCODED_FIELD_RE.match(value)
        if m:
            return m.group(2)
    return value


def display_name(doc):
    """Best-effort human name for the certificate holder."""
    if not isinstance(doc, dict):
        return None
    data = doc.get("data")
    if isinstance(data, dict):
        recipient = data.get("recipient")
        if isinstance(recipient, dict):
            name = decode_field(recipient.get("name"))
            if name:
                return name
        name = decode_field(data.get("name"))
        if name:
            return name
    subject = doc.get("credentialSubject")
    if not isinstance(subject, dict):
        cred = doc.get("credential")
        subject = cred.get("credentialSubject") if isinstance(cred, dict) else None
    if isinstance(subject, dict):
        return subject.get("name") or subject.get("id")
    return None


def issued_date(doc):
    if not isinstance(doc, dict):
        return None
    if doc.get("issueDate"):
        return doc["issueDate"]
    data = doc.get("data")
    if isinstance(data, dict):
        return decode_field(data.get("issuedOn")) or None
    return None


def validate_opencert(doc):
    """Return a list of validation errors (empty list = valid).

    Accepts the two OpenCert shapes seen in the wild:
      * OpenAttestation documents  — 'data' plus 'version'/'schema'/'signature'/'proof'
        (e.g. NTU PACE certificates from render.ntu.edu.sg)
      * W3C VerifiableCredentials  — '@context' plus 'credentialSubject'/'credential'
    """
    if not isinstance(doc, dict):
        return ["certificate must be a JSON object"]
    if isinstance(doc.get("data"), dict) and (
            "version" in doc or "schema" in doc or "signature" in doc or "proof" in doc):
        return []
    if "@context" in doc and ("credentialSubject" in doc or "credential" in doc):
        return []
    return ["unrecognized OpenCert format — expected an OpenAttestation document "
            "('data' plus 'version'/'schema'/'signature'/'proof') or a W3C credential "
            "('@context' plus 'credentialSubject')"]


# ------------------------------------------------------------- multipart

def parse_multipart(body, content_type):
    """Parse a multipart/form-data body using the stdlib email parser."""
    header = ("Content-Type: " + content_type + "\r\n\r\n").encode("utf-8")
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(header + body)
    parts = []
    for i, part in enumerate(msg.iter_parts()):
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        data = part.get_payload(decode=True) or b""
        parts.append({"name": name, "filename": filename, "data": data, "index": i})
    return parts


# ----------------------------------------------------------------- html

VIEWER_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ — OpenCert Viewer</title>
<style>
  :root { color-scheme: light dark;
    --fg: #1c1e21; --muted: #6b7280; --card: #ffffff; --line: #e5e7eb;
    --accent: #2563eb; --bg: #f6f7f9; --code-bg: #0f172a; --code-fg: #e2e8f0; }
  @media (prefers-color-scheme: dark) {
    --fg: #e5e7eb; --muted: #9ca3af; --card: #111827; --line: #273043;
    --accent: #60a5fa; --bg: #0b1017; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI",
    Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--fg); }
  .wrap { max-width: 720px; margin: 0 auto; padding: 40px 20px 80px; }
  .badge { display: inline-block; font-size: 12px; font-weight: 600; letter-spacing: .06em;
    text-transform: uppercase; color: var(--accent); margin-bottom: 12px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin: 0 0 28px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 18px 22px; margin-bottom: 16px; }
  .card h2 { font-size: 12px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    color: var(--muted); margin: 0 0 10px; }
  .kv { display: flex; justify-content: space-between; gap: 16px; padding: 5px 0;
    border-bottom: 1px solid var(--line); }
  .kv:last-child { border-bottom: 0; }
  .kv .k { color: var(--muted); flex-shrink: 0; }
  .kv .v { font-weight: 500; text-align: right; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 24px; }
  button { font: inherit; font-size: 13px; font-weight: 500; padding: 8px 14px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  pre { margin: 0; background: var(--code-bg); color: var(--code-fg); padding: 16px;
    border-radius: 10px; overflow: auto; font-size: 12.5px; line-height: 1.5;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  details summary { cursor: pointer; font-size: 13px; font-weight: 500; color: var(--accent);
    padding: 10px 0; }
  .hidden { display: none; }
  .copied { color: var(--accent); font-size: 13px; align-self: center; }
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">OpenCert Viewer</div>
  <h1>__TITLE__</h1>
  <p class="sub">__SUBTITLE__</p>

  <div class="actions">
    <button class="primary" onclick="copyUrl()">Copy certificate URL</button>
    <button onclick="toggleJson()">Show raw JSON</button>
  </div>
  <div id="copied" class="copied hidden">Copied ✓</div>

  __SECTIONS__

  <details>
    <summary>Raw JSON</summary>
    <pre id="raw">__RAW__</pre>
  </details>
</div>
<script>
  const CERT_URL = "__CERT_URL__";
  function copyUrl() {
    navigator.clipboard.writeText(CERT_URL).then(() => {
      const el = document.getElementById("copied");
      el.classList.remove("hidden");
      setTimeout(() => el.classList.add("hidden"), 1500);
    });
  }
  function toggleJson() {
    const d = document.querySelector("details");
    d.open = !d.open;
  }
</script>
</body>
</html>
"""

LANDING_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenCert API</title>
<style>
  :root { color-scheme: light dark; --fg:#1c1e21; --muted:#6b7280; --card:#fff;
    --line:#e5e7eb; --bg:#f6f7f9; --accent:#2563eb; --code-bg:#0f172a; --code-fg:#e2e8f0; }
  @media (prefers-color-scheme: dark) { --fg:#e5e7eb; --muted:#9ca3af; --card:#111827;
    --line:#273043; --bg:#0b1017; --accent:#60a5fa; }
  body { margin:0; font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:var(--bg); color:var(--fg); }
  .wrap { max-width:760px; margin:0 auto; padding:48px 20px 80px; }
  h1 { font-size:28px; } code { font-family:ui-monospace,Menlo,monospace; font-size:.9em;
    background:rgba(127,127,127,.15); padding:1px 5px; border-radius:4px; }
  pre { background:var(--code-bg); color:var(--code-fg); padding:14px 16px; border-radius:10px;
    overflow:auto; font-size:13px; font-family:ui-monospace,Menlo,monospace; }
  table { border-collapse:collapse; width:100%; margin:8px 0 28px; }
  td { padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  .m { color:var(--accent); font-weight:600; white-space:nowrap; }
</style>
</head>
<body><div class="wrap">
  <h1>OpenCert API</h1>
  <p>Upload an OpenCert file and get back a hosted URL plus a link that opens it in the
  certificate viewer.</p>
  <table>
    <tr><td class="m">POST</td><td><code>/api/certificates</code></td><td>Upload an OpenCert — multipart file part <code>file</code>, or a raw <code>application/json</code> body</td></tr>
    <tr><td class="m">GET</td><td><code>/api/certificates</code></td><td>List stored certificates</td></tr>
    <tr><td class="m">GET</td><td><code>/api/certificates/&lt;id&gt;</code></td><td>Fetch a certificate as JSON</td></tr>
    <tr><td class="m">GET</td><td><code>/view/&lt;id&gt;</code></td><td>Open the certificate in the built-in viewer (for local testing)</td></tr>
  </table>
  <h2>Upload example</h2>
  <pre>curl -F "file=@sample.opencert.json" http://localhost:8080/api/certificates</pre>
  <p>Response:</p>
  <pre>{{
  "id": "0a1b2c3d4e5f6a7b",
  "name": "Alice Nguyen",
  "url": "http://localhost:8080/api/certificates/0a1b2c3d4e5f6a7b",
  "viewerUrl": "https://www.opencerts.io/http%3A%2F%2Flocalhost%3A8080%2Fapi%2Fcertificates%2F0a1b2c3d4e5f6a7b"
}}</pre>
  <p>Open <code>viewerUrl</code> to view the certificate. By default it points to
  <code>https://www.opencerts.io/</code> with the hosted <code>url</code> appended.
  Change it by setting <code>OPENCERT_VIEWER_URL</code> (e.g.
  <code>https://viewer.example.com/?cert=</code>).</p>
</div></body></html>
"""


def kv_row(k, v):
    return ('<div class="kv"><span class="k">%s</span><span class="v">%s</span></div>'
            % (html.escape(str(k)), html.escape(str(v))))


def finish_page(title, subtitle, sections, doc, cert_url):
    return VIEWER_TEMPLATE \
        .replace("__TITLE__", html.escape(title)) \
        .replace("__SUBTITLE__", html.escape(subtitle)) \
        .replace("__SECTIONS__", "\n  ".join(sections)) \
        .replace("__RAW__", html.escape(json.dumps(doc, indent=2, ensure_ascii=False))) \
        .replace("__CERT_URL__", html.escape(cert_url, quote=True))


def render_viewer(doc, cert_url):
    """Render the built-in viewer page. Supports both OpenCert shapes."""
    if isinstance(doc.get("data"), dict) and \
            ("version" in doc or "schema" in doc or "signature" in doc or "proof" in doc):
        return render_viewer_openattestation(doc, cert_url)
    return render_viewer_w3c(doc, cert_url)


def render_viewer_w3c(doc, cert_url):
    subject = doc.get("credentialSubject")
    if not isinstance(subject, dict):
        cred = doc.get("credential")
        subject = cred.get("credentialSubject") if isinstance(cred, dict) else None
    subject = subject or {}
    issuer = doc.get("issuer")
    issuer_name = issuer.get("name") if isinstance(issuer, dict) else (issuer or "—")
    title = display_name(doc) or "OpenCert"
    subtitle = "Issued by %s" % issuer_name

    sections = []

    if isinstance(subject, dict) and subject:
        rows = []
        for k, v in subject.items():
            if k != "claims" and not isinstance(v, (dict, list)):
                rows.append(kv_row(k, v))
        claims = subject.get("claims")
        if isinstance(claims, list) and claims:
            claim_rows = []
            for c in claims:
                if isinstance(c, dict):
                    name = c.get("name") or c.get("type") or ""
                    claim_rows.append(kv_row(name, c.get("value", "")))
                else:
                    claim_rows.append(kv_row("claim", c))
            if claim_rows:
                sections.append('<div class="card"><h2>Claims</h2>%s</div>'
                                % "".join(claim_rows))
        if rows:
            sections.insert(0, '<div class="card"><h2>Subject</h2>%s</div>' % "".join(rows))

    meta = []
    for k in ("id", "issueDate", "expirationDate"):
        if doc.get(k):
            meta.append(kv_row(k, doc[k]))
    meta.append(kv_row("Issuer", issuer_name))
    sections.append('<div class="card"><h2>Details</h2>%s</div>' % "".join(meta))

    return finish_page(title, subtitle, sections, doc, cert_url)


def render_viewer_openattestation(doc, cert_url):
    data = doc["data"]
    title = decode_field(data.get("name")) or "OpenCert"
    issuers = data.get("issuers")
    issuer = issuers[0] if isinstance(issuers, list) and issuers and isinstance(issuers[0], dict) else {}
    issuer_name = decode_field(issuer.get("issuerName") or issuer.get("name")) or "—"
    subtitle = "Issued by %s" % issuer_name

    sections = []

    recipient = data.get("recipient")
    if isinstance(recipient, dict):
        rows = []
        for k in ("name", "email", "idType", "nric"):
            v = decode_field(recipient.get(k))
            if v not in (None, ""):
                rows.append(kv_row(k, v))
        if rows:
            sections.append('<div class="card"><h2>Recipient</h2>%s</div>' % "".join(rows))

    extra = (data.get("additionalData") or {}).get("extra")
    if isinstance(extra, dict) and extra:
        rows = []
        course = " ".join(str(decode_field(extra.get("courseTitle%d" % i)) or "").strip()
                          for i in (1, 2, 3)).strip()
        if course:
            rows.append(kv_row("Course", course))
        for k, label in (("completionText", "Awarded for"),
                         ("duration", "Duration"),
                         ("certSignatory1", "Signatory"),
                         ("certSignatory2", "Signatory (name)")):
            v = decode_field(extra.get(k))
            if v not in (None, ""):
                rows.append(kv_row(label, v))
        if rows:
            sections.append('<div class="card"><h2>Certificate</h2>%s</div>' % "".join(rows))

    meta = []
    issued = decode_field(data.get("issuedOn"))
    if issued:
        meta.append(kv_row("Issued on", issued))
    template = data.get("$template")
    if isinstance(template, dict):
        tname = decode_field(template.get("name"))
        if tname:
            meta.append(kv_row("Template", tname))
    if issuer.get("url"):
        meta.append(kv_row("Issuer URL", decode_field(issuer.get("url"))))
    meta.append(kv_row("Format", doc.get("version", "OpenAttestation")))
    sections.append('<div class="card"><h2>Details</h2>%s</div>' % "".join(meta))

    return finish_page(title, subtitle, sections, doc, cert_url)


# -------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "OpenCertAPI/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[opencert-api] %s %s" % (self.address_string(), fmt % args), flush=True)

    # -- helpers

    def _send(self, code, body, content_type):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, indent=2, ensure_ascii=False) + "\n",
                   "application/json; charset=utf-8")

    def _html(self, code, page):
        self._send(code, page, "text/html; charset=utf-8")

    def _base(self):
        host = self.headers.get("Host") or "localhost:%d" % PORT
        return "http://%s" % host

    def viewer_url_for(self, cert_id, cert_url):
        if VIEWER_URL_PREFIX:
            return VIEWER_URL_PREFIX + quote(cert_url, safe="")
        return "/view/%s" % cert_id

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            return None, 413
        return self.rfile.read(length), None

    # -- verbs

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if path == "/":
                return self._html(200, LANDING_TEMPLATE)
            if path == "/api/certificates":
                return self._json(200, {"certificates": list_certificates()})
            m = re.fullmatch(r"/api/certificates/([a-f0-9]{16})", path)
            if m:
                doc = load_certificate(m.group(1))
                if doc is None:
                    return self._json(404, {"error": "certificate not found"})
                return self._json(200, doc)
            m = re.fullmatch(r"/view/([a-f0-9]{16})", path)
            if m:
                doc = load_certificate(m.group(1))
                if doc is None:
                    return self._html(404, "<h1>404 — certificate not found</h1>")
                cert_url = "%s/api/certificates/%s" % (self._base(), m.group(1))
                return self._html(200, render_viewer(doc, cert_url))
            return self._json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001 — report, don't drop the connection
            return self._json(500, {"error": str(e)})

    def _fetch_url(self, ext_url):
        """Fetch a certificate from an external URL. Returns (raw, error_response)."""
        parsed = urlparse(ext_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None, (400, {"error": "'url' must be an http(s) URL"})
        try:
            req = urllib.request.Request(ext_url, headers={"User-Agent": "OpenCertAPI/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read(MAX_BODY + 1)
        except Exception as e:  # noqa: BLE001 — network failures become a 400
            return None, (400, {"error": "failed to fetch url", "url": ext_url, "detail": str(e)})
        if len(raw) > MAX_BODY:
            return None, (413, {"error": "remote file too large (max 5 MB)", "url": ext_url})
        return raw, None

    def _ingest(self, raw):
        """Shared path: JSON parse -> validate -> store -> 201 response."""
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return self._json(400, {"error": "invalid JSON", "detail": str(e)})

        errors = validate_opencert(doc)
        if errors:
            return self._json(400, {"error": "not a valid OpenCert", "details": errors})

        cert_id = save_certificate(doc)
        cert_url = "%s/api/certificates/%s" % (self._base(), cert_id)
        return self._json(201, {
            "id": cert_id,
            "name": display_name(doc),
            "url": cert_url,
            "viewerUrl": self.viewer_url_for(cert_id, cert_url),
            "created": True,
        })

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path != "/api/certificates":
            return self._json(404, {"error": "not found"})
        try:
            # Option 1: fetch the certificate from an external URL
            qs = parse_qs(urlparse(self.path).query)
            ext_url = (qs.get("url") or [None])[0]
            if ext_url:
                raw, err = self._fetch_url(ext_url)
                if err:
                    return self._json(err[0], err[1])
                return self._ingest(raw)

            # Option 2: upload the certificate in the request body
            body, err = self._read_body()
            if err:
                return self._json(err, {"error": "request too large (max 5 MB)"})
            ctype = (self.headers.get("Content-Type") or "").lower()

            if "application/json" in ctype:
                raw = body or b"{}"
            elif "multipart/form-data" in ctype:
                parts = parse_multipart(body or b"", self.headers.get("Content-Type"))
                if not parts:
                    return self._json(400, {"error": "no file part in multipart body"})
                # prefer an explicitly named "file" part, else the first file
                named = [p for p in parts if p["name"] == "file" and p["data"]]
                with_file = [p for p in parts if p["filename"] and p["data"]]
                pick = (named or with_file or parts)[0]
                raw = pick["data"]
            else:
                return self._json(415, {
                    "error": "unsupported Content-Type",
                    "expected": ["multipart/form-data (file part)", "application/json"],
                })
            return self._ingest(raw)
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("OpenCert API listening on http://%s:%d" % (HOST, PORT), flush=True)
    print("  docs:     http://localhost:%d/" % PORT)
    print("  upload:   curl -F \"file=@sample.opencert.json\" http://localhost:%d/api/certificates" % PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
