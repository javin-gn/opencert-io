#!/usr/bin/env python3
"""OpenCert API — ingest an OpenCert from a file URL and open it in a viewer.

Endpoints:
  POST /api/certificates?url=<file-url>   fetch, validate and host the OpenCert,
                                          then 302-redirect to the viewer
  GET  /api/certificates          list stored certificates
  GET  /api/certificates/<id>     fetch a stored certificate as JSON
  GET  /view/<id>                 open the certificate in the built-in viewer
  GET  /submit                    web form to ingest a certificate (default page)
  GET  /                          redirects to /submit

Environment:
  PORT                  listen port (default 8080)
  HOST                  bind address (default 0.0.0.0)
  CERT_DATA_DIR         storage directory (default ./data/certificates)
  OPENCERT_VIEWER_URL   base URL of the OpenCert viewer (default
                        https://www.opencerts.io/). For opencerts.io the link
                        is a ?q= DOCUMENT action pointing at the hosted
                        certificate; for other viewers the hosted certificate
                        URL is appended. A built-in viewer page is also served
                        at /view/<id>.

Stdlib only — no third-party dependencies.
"""

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


# Matches JavaScript's encodeURI(): reserved/mark characters (; , / ? : @ & = + $ - _ . ! ~ * ' ( ) #)
# stay literal; everything else (notably '"', '{', '}', space) is percent-encoded.
ENCODE_URI_SAFE = "!#$&'()*+,-./:;=?@_~"


def encode_uri(s):
    return quote(s, safe=ENCODE_URI_SAFE)


def opencerts_viewer_url(cert_url):
    """Deep-link format opencerts.io actually supports.

    A bare path (https://www.opencerts.io/<url>) is not a route — the SPA falls
    back to its upload page. The app reads a ?q= parameter holding a
    URL-encoded OpenAttestation action; for a DOCUMENT action it fetches
    payload.uri itself."""
    action = json.dumps(
        {"type": "DOCUMENT", "payload": {"uri": cert_url}}, separators=(",", ":"))
    return "https://www.opencerts.io/?q=" + encode_uri(action)


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

LINK_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Build viewer link — OpenCert API</title>
<style>
  :root { color-scheme: light dark; --fg:#1c1e21; --muted:#6b7280; --card:#fff;
    --line:#e5e7eb; --bg:#f6f7f9; --accent:#2563eb; --code-bg:#0f172a; --code-fg:#e2e8f0; }
  @media (prefers-color-scheme: dark) { --fg:#e5e7eb; --muted:#9ca3af; --card:#111827;
    --line:#273043; --bg:#0b1017; --accent:#60a5fa; }
  body { margin:0; font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:var(--bg); color:var(--fg); }
  .wrap { max-width:760px; margin:0 auto; padding:48px 20px 80px; }
  h1 { font-size:28px; }
  label { display:block; font-weight:600; margin:18px 0 6px; }
  input[type=text] { font:inherit; width:100%; padding:10px 12px; border:1px solid var(--line);
    border-radius:8px; background:var(--card); color:var(--fg); box-sizing:border-box; }
  code { font-family:ui-monospace,Menlo,monospace; font-size:.85em; overflow-wrap:anywhere; }
  .row { display:flex; gap:12px; align-items:flex-start; margin:12px 0; }
  .row .k { color:var(--muted); flex-shrink:0; width:104px; padding-top:9px; }
  .row code { background:var(--code-bg); color:var(--code-fg); flex:1; padding:9px 12px; border-radius:8px; }
  .actions { display:flex; gap:10px; align-items:center; margin-top:18px; }
  button, a.btn { font:inherit; font-size:14px; font-weight:500; padding:9px 16px; border-radius:8px;
    border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; text-decoration:none; }
  .primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  .copied { color:var(--accent); font-size:13px; }
  .hidden { display:none; }
  .hint { color:var(--muted); font-size:13.5px; margin-top:28px; }
  .hint code { background:rgba(127,127,127,.15); padding:1px 5px; border-radius:4px; }
</style>
</head>
<body><div class="wrap">
  <h1>Build a viewer link</h1>
  <p>Paste a gist or certificate file URL. This builds the <code>opencerts.io</code>
  viewer link — a URL-encoded <code>DOCUMENT</code> action the viewer opens by
  fetching the file itself — ready to share (e.g. as a LinkedIn link).</p>

  <label for="in">Gist or certificate file URL</label>
  <input id="in" type="text" spellcheck="false"
         placeholder="https://gist.github.com/&lt;user&gt;/&lt;gist-id&gt;  — or any http(s) file URL"
         oninput="build()">

  <div class="row"><span class="k">File URL</span><code id="file">—</code></div>
  <div class="row"><span class="k">Viewer link</span><code id="out">—</code></div>

  <div class="actions">
    <button class="primary" onclick="copy()">Copy viewer link</button>
    <a id="open" class="btn" target="_blank" rel="noopener" href="#">Open in viewer</a>
    <span id="copied" class="copied hidden">Copied &#10003;</span>
  </div>

  <p class="hint">Accepts <code>gist.github.com/&lt;user&gt;/&lt;id&gt;</code> in any form
  (page URL, <code>/raw</code>, with file name) — it is rewritten to the raw file —
  plus any direct http(s) file URL. The viewer fetches the file from its own origin,
  so the URL must stay public and must allow cross-origin reads.</p>
</div>
<script>
  function normalize(v) {
    v = (v || "").trim();
    var m = v.match(/^(https?:\/\/gist\.github\.com\/([^/]+)\/([0-9a-f]{32})(?:\/([^/?#]*))?(?:[?#].*)?$/i);
    if (m) {
      var sub = m[4];
      sub = (!sub || sub.toLowerCase() === "raw") ? "raw" : "raw/" + encodeURIComponent(sub);
      return m[1] + "://gist.githubusercontent.com/" + m[2] + "/" + m[3] + "/" + sub;
    }
    return /^https?:\/\//i.test(v) ? v : null;
  }
  function build() {
    var fileUrl = normalize(document.getElementById("in").value);
    var f = document.getElementById("file"), o = document.getElementById("out"),
        a = document.getElementById("open");
    if (!fileUrl) {
      f.textContent = o.textContent = "—";
      a.href = "#";
      return;
    }
    f.textContent = fileUrl;
    var link = "https://www.opencerts.io/?q=" + encodeURI(
        JSON.stringify({type: "DOCUMENT", payload: {uri: fileUrl}}));
    o.textContent = link;
    a.href = link;
  }
  function copy() {
    var t = document.getElementById("out").textContent;
    if (!t || t === "—") return;
    var done = function() {
      var c = document.getElementById("copied");
      c.classList.remove("hidden");
      setTimeout(function() { c.classList.add("hidden"); }, 1500);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(t).then(done, function() { prompt("Copy the viewer link:", t); });
    else prompt("Copy the viewer link:", t);
  }
</script>
</body>
</html>
"""


SUBMIT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Submit a certificate — OpenCert API</title>
<style>
  :root { color-scheme: light dark; --fg:#1c1e21; --muted:#6b7280; --card:#fff;
    --line:#e5e7eb; --bg:#f6f7f9; --accent:#2563eb; --ok:#16a34a; --err:#dc2626; }
  @media (prefers-color-scheme: dark) { --fg:#e5e7eb; --muted:#9ca3af; --card:#111827;
    --line:#273043; --bg:#0b1017; --accent:#60a5fa; --ok:#4ade80; --err:#f87171; }
  body { margin:0; font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:var(--bg); color:var(--fg); }
  .wrap { max-width:640px; margin:0 auto; padding:48px 20px 80px; }
  h1 { font-size:28px; margin:0 0 8px; }
  p.sub { color:var(--muted); margin:0 0 24px; }
  label { display:block; font-weight:600; margin:0 0 6px; }
  .row { display:flex; gap:10px; align-items:stretch; }
  input[type=text] { font:inherit; flex:1; min-width:0; padding:10px 12px; border:1px solid var(--line);
    border-radius:8px; background:var(--card); color:var(--fg); box-sizing:border-box; }
  button { font:inherit; font-size:14px; font-weight:600; padding:10px 18px; border-radius:8px;
    border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer; }
  button:disabled { opacity:.6; cursor:default; }
  #panel { margin-top:20px; border:1px solid var(--line); border-radius:10px; padding:16px 18px;
    background:var(--card); display:none; }
  #panel.show { display:block; }
  #panel.ok { border-left:4px solid var(--ok); }
  #panel.err { border-left:4px solid var(--err); }
  #panel h2 { font-size:14px; margin:0 0 10px; }
  #panel.ok h2 { color:var(--ok); }
  #panel.err h2 { color:var(--err); }
  .kv { display:flex; justify-content:space-between; gap:16px; padding:5px 0;
    border-bottom:1px solid var(--line); font-size:13.5px; }
  .kv:last-child { border-bottom:0; }
  .kv .k { color:var(--muted); flex-shrink:0; }
  .kv .v { font-weight:500; text-align:right; overflow-wrap:anywhere; }
  .kv .v.url-row { display:flex; align-items:center; justify-content:flex-end; gap:8px; }
  .kv .v.url-row .url-text { overflow-wrap:anywhere; }
  .copy-btn { font:inherit; font-size:12px; font-weight:600; padding:3px 10px; border-radius:6px;
    border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; flex-shrink:0; }
  #panel a.btn { display:inline-block; margin-top:12px; font-weight:600; color:var(--accent);
    text-decoration:none; }
  ul.errs { margin:6px 0 0; padding-left:18px; font-size:13.5px; }
</style>
</head>
<body><div class="wrap">
  <h1>Opencerts Sharable Link Tool</h1>
  <h3>What is OpenCerts?</h3>
  <p class="sub">OpenCerts is an open-source, blockchain-based platform originally developed by GovTech Singapore (the Government Technology Agency of Singapore) alongside local educational institutions and industry partners. It is designed for issuing and verifying tamper-resistant digital academic certificates and transcripts.</p>
  <h3>Purpose of this tool</h3>
  <p class="sub">OpenCerts certificates are plain text files. Unfortunately, platforms like Linkedin don't know how to handle such files, and they don't provide the users a simple way to share them.</p>
  <p class="sub">This tool help to share your certificate by generating a sharable link using the below process:
  <ul>
  <li>React your sensitive information using GovTech's <a href="https://privacy-filter.netlify.app">OpenAttestation Privacy Filter</a> and download it</li>
  <li>Host/deploy your downloaded redacted certificate somewhere (i.e., your certificate must be accessible from a URL)</li> 
  <li>Paste the Hosted/deployed certificate URL and submit to generate its OpenCerts link below.</li>
  <li>Copy the link and share it on Linkedin or your preferred platform</li>
  </p>
  <form id="f">
    <label for="url">Hosted/deployed certificate file URL</label>
    <div class="row">
      <input id="url" type="text" name="url" spellcheck="false" autocomplete="off"
             placeholder="https://example.com/certificate.opencert" required>
      <button id="btn" type="submit">Submit</button>
    </div>
  </form>

  <div id="panel"></div>
</div>
<script>
  var form = document.getElementById("f");
  var btn = document.getElementById("btn");
  var panel = document.getElementById("panel");

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\\"": "&quot;", "'": "&#39;" }[c];
    });
  }

  function kv(k, v) {
    return '<div class="kv"><span class="k">' + escapeHtml(k) + '</span>' +
           '<span class="v">' + escapeHtml(v) + '</span></div>';
  }

  function kvWithCopy(k, v) {
    return '<div class="kv"><span class="k">' + escapeHtml(k) + '</span>' +
           '<span class="v url-row"><span class="url-text">' + escapeHtml(v) + '</span>' +
           '<button type="button" class="copy-btn" data-url="' + escapeHtml(v) +
           '" onclick="copyViewerUrl(this)">Copy</button></span></div>';
  }

  function copyViewerUrl(button) {
    var url = button.getAttribute("data-url");
    var reset = function () {
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(function () {
        button.textContent = "Copied ✓";
        reset();
      }, function () {
        prompt("Copy this link:", url);
      });
    } else {
      prompt("Copy this link:", url);
    }
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = document.getElementById("url").value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.textContent = "Submitting…";
    panel.className = "show";
    panel.innerHTML = "<p>Fetching and validating…</p>";

    fetch("/api/certificates?url=" + encodeURIComponent(url) + "&format=json", { method: "POST" })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (res.ok) {
          var b = res.body;
          var rows = "";
          if (b.name) rows += kv("Name", b.name);
          if (b.issued) rows += kv("Issued", b.issued);
          rows += kvWithCopy("Viewer URL", b.viewerUrl);
          panel.className = "show ok";
          panel.innerHTML = "<h2>Certificate ingested</h2>" + rows +
            '<a class="btn" href="' + escapeHtml(b.viewerUrl) + '" target="_blank" rel="noopener">View certificate →</a>';
        } else {
          var b = res.body || {};
          var details = "";
          if (Array.isArray(b.details) && b.details.length) {
            details = "<ul class=\\"errs\\">" + b.details.map(function (d) {
              return "<li>" + escapeHtml(d) + "</li>";
            }).join("") + "</ul>";
          } else if (b.detail) {
            details = "<p>" + escapeHtml(b.detail) + "</p>";
          }
          panel.className = "show err";
          panel.innerHTML = "<h2>" + escapeHtml(b.error || "Request failed") + "</h2>" + details;
        }
      })
      .catch(function (err) {
        panel.className = "show err";
        panel.innerHTML = "<h2>Request failed</h2><p>" + escapeHtml(err.message || err) + "</p>";
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = "Submit";
      });
  });
</script>
</body>
</html>
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

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _base(self):
        host = self.headers.get("Host") or "localhost:%d" % PORT
        return "http://%s" % host

    def viewer_url_for(self, cert_id, cert_url):
        prefix = VIEWER_URL_PREFIX
        if not prefix:
            return "/view/%s" % cert_id
        if urlparse(prefix).netloc in ("www.opencerts.io", "opencerts.io"):
            return opencerts_viewer_url(cert_url)
        return prefix + quote(cert_url, safe="")

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
                return self._redirect("/submit")
            if path == "/link":
                return self._html(200, LINK_TEMPLATE)
            if path == "/submit":
                return self._html(200, SUBMIT_TEMPLATE)
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

    def _ingest(self, raw, ext_url, as_json=False):
        """Shared path: JSON parse -> validate -> store -> redirect to the viewer.

        With as_json=True, respond with a JSON summary instead of redirecting,
        and build the viewer link straight from the submitted url rather than
        storing a copy (used by the /submit page)."""
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return self._json(400, {"error": "invalid JSON", "detail": str(e)})

        errors = validate_opencert(doc)
        if errors:
            return self._json(400, {"error": "not a valid OpenCert", "details": errors})

        if as_json:
            return self._json(200, {
                "viewerUrl": self.viewer_url_for(None, ext_url),
                "name": display_name(doc),
                "issued": issued_date(doc),
            })

        cert_id = save_certificate(doc)
        cert_url = "%s/api/certificates/%s" % (self._base(), cert_id)
        self._redirect(self.viewer_url_for(cert_id, cert_url))

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path != "/api/certificates":
            return self._json(404, {"error": "not found"})
        try:
            # The certificate file URL comes from the request params;
            # the server fetches it — no file uploads.
            qs = parse_qs(urlparse(self.path).query)
            ext_url = (qs.get("url") or [None])[0]
            as_json = (qs.get("format") or [None])[0] == "json"
            if not ext_url:
                return self._json(400, {
                    "error": "missing required 'url' query parameter",
                    "hint": "POST /api/certificates?url=<certificate-file-url>",
                })
            if as_json and not VIEWER_URL_PREFIX:
                return self._json(400, {
                    "error": "no external viewer configured (OPENCERT_VIEWER_URL is empty); "
                             "format=json needs a viewer to link to since it doesn't host a copy",
                })
            raw, err = self._fetch_url(ext_url)
            if err:
                return self._json(err[0], err[1])
            return self._ingest(raw, ext_url, as_json=as_json)
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("OpenCert API listening on http://%s:%d" % (HOST, PORT), flush=True)
    print("  docs:     http://localhost:%d/" % PORT)
    print("  ingest:   curl -X POST \"http://localhost:%d/api/certificates?url=&lt;certificate-file-url&gt;\"" % PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
