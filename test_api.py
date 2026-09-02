#!/usr/bin/env python3
"""End-to-end tests for the OpenCert API. Run: python3 test_api.py"""

import json
import os
import shutil
import tempfile
import threading
import urllib.error
import urllib.request

import server

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "examples", "sample.opencert.json")
# real OpenAttestation-format certificate (NTU PACE)
SAMPLE_OA = os.path.join(HERE, "examples",
                         "(SCTP) Advanced Professional Certificate in Data Science and AI.opencert")
PASS = 0


def check(label, cond, extra=""):
    global PASS
    if not cond:
        raise AssertionError("FAIL: %s %s" % (label, extra))
    PASS += 1
    print("  ok - %s" % label)


def req(port, method, path, body=None, ctype=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    r = urllib.request.Request(url, data=body, method=method)
    if ctype and body is not None:
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def multipart_body(field, filename, data):
    boundary = "testboundary123"
    head = (
        "--%s\r\n"
        'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
        "Content-Type: application/json\r\n\r\n" % (boundary, field, filename)
    ).encode()
    return head + data + ("\r\n--%s--\r\n" % boundary).encode()


def main():
    tmp = tempfile.mkdtemp(prefix="opencert-test-")
    server.DATA_DIR = os.path.join(tmp, "certificates")

    import http.server
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    with open(SAMPLE, "rb") as f:
        sample_bytes = f.read()
    sample = json.loads(sample_bytes)

    print("POST /api/certificates (multipart file part)")
    status, body = req(port, "POST", "/api/certificates",
                       multipart_body("file", "sample.opencert.json", sample_bytes),
                       "multipart/form-data; boundary=testboundary123")
    assert status == 201, body
    created = json.loads(body)
    check("returns 201", True)
    check("has id", bool(created.get("id")))
    check("has url", created["url"].endswith("/api/certificates/%s" % created["id"]))
    import urllib.parse as ulip
    expected = "https://www.opencerts.io/" + ulip.quote(created["url"], safe="")
    check("viewerUrl points to opencerts.io", created["viewerUrl"] == expected)
    check("name from credentialSubject", created.get("name") == "Alice Nguyen")
    cid = created["id"]

    print("GET /api/certificates/<id>")
    status, body = req(port, "GET", "/api/certificates/%s" % cid)
    assert status == 200, body
    check("round-trips the certificate", json.loads(body) == sample)

    print("GET /view/<id> (built-in viewer)")
    status, body = req(port, "GET", "/view/%s" % cid)
    page = body.decode()
    assert status == 200
    check("viewer renders holder name", "Alice Nguyen" in page)
    check("viewer renders issuer", "Example Academy" in page)
    check("viewer renders claims", "Advanced Python" in page and "95%" in page)
    check("viewer embeds certificate URL", "/api/certificates/%s" % cid in page)

    print("POST /api/certificates (raw JSON body)")
    status, body = req(port, "POST", "/api/certificates", sample_bytes, "application/json")
    assert status == 201, body
    check("accepts raw JSON upload", True)

    print("POST /api/certificates?url=<external-url>")
    # serve the sample on a throwaway server to act as the "external url"
    import functools
    import http.server as _hs
    handler = functools.partial(
        _hs.SimpleHTTPRequestHandler, directory=os.path.join(HERE, "examples"))
    file_srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    file_port = file_srv.server_address[1]
    threading.Thread(target=file_srv.serve_forever, daemon=True).start()

    ext_url = "http://127.0.0.1:%d/sample.opencert.json" % file_port
    status, body = req(port, "POST", "/api/certificates?url=%s" % ext_url)
    assert status == 201, body
    via_url = json.loads(body)
    check("fetches and stores cert from external url", True)
    check("extracts name from fetched cert", via_url.get("name") == "Alice Nguyen", str(via_url))
    check("viewerUrl points to opencerts.io",
          via_url["viewerUrl"].startswith("https://www.opencerts.io/"))

    # fetch it back and confirm it matches the original
    status, body = req(port, "GET", "/api/certificates/%s" % via_url["id"])
    check("fetched cert round-trips", status == 200 and json.loads(body) == sample)

    # error cases for url ingestion
    status, body = req(port, "POST", "/api/certificates?url=ftp%3A%2F%2Fnope")
    check("rejects non-http(s) url (400)", status == 400)
    status, body = req(port, "POST",
                       "/api/certificates?url=http%3A%2F%2F127.0.0.1%3A1%2Fnope")
    check("reports fetch failure (400)", status == 400)
    file_srv.shutdown()

    print("POST /api/certificates (real OpenAttestation .opencert file)")
    with open(SAMPLE_OA, "rb") as f:
        oa_bytes = f.read()
    status, body = req(port, "POST", "/api/certificates",
                       multipart_body("file", "certificate.opencert", oa_bytes),
                       "multipart/form-data; boundary=testboundary123")
    assert status == 201, body
    oa = json.loads(body)
    check("accepts NTU PACE .opencert file", True)
    check("extracts recipient name", oa.get("name") == "Gn Cher Teck", str(oa))
    check("viewerUrl points to opencerts.io",
          oa["viewerUrl"].startswith("https://www.opencerts.io/"), oa["viewerUrl"])

    print("GET /view/<id> (built-in viewer, OpenAttestation format)")
    status, body = req(port, "GET", "/view/%s" % oa["id"])
    page = body.decode()
    assert status == 200
    check("viewer shows decoded holder name", "Gn Cher Teck" in page)
    check("viewer shows decoded issuer", "Nanyang Technological University" in page
          or "NTU PACE" in page)
    check("viewer shows decoded course", "Data Science and AI" in page)
    # rendered rows show decoded values, not the raw '<uuid>:string:' encoding
    import re as _re
    rendered = _re.sub(r"<pre id=\"raw\">.*?</pre>", "", page, flags=_re.S)
    check("rendered rows are decoded (no :string: noise)", ":string:" not in rendered)

    print("GET /api/certificates (list)")
    status, body = req(port, "GET", "/api/certificates")
    listing = json.loads(body)
    assert status == 200
    check("lists all four certificates", len(listing["certificates"]) == 4)
    check("list shows decoded name + issued date",
          any(c["name"] == "Gn Cher Teck" and c["issued"]
              for c in listing["certificates"]))

    print("error cases")
    status, body = req(port, "POST", "/api/certificates",
                       multipart_body("file", "bad.json", b'{"foo": 1}'),
                       "multipart/form-data; boundary=testboundary123")
    check("rejects non-OpenCert JSON (400)", status == 400)
    check("explains why", "details" in json.loads(body))

    status, body = req(port, "POST", "/api/certificates", b"not json", "application/json")
    check("rejects invalid JSON (400)", status == 400)

    status, body = req(port, "POST", "/api/certificates", b"hello", "text/plain")
    check("rejects unsupported content type (415)", status == 415)

    status, body = req(port, "GET", "/api/certificates/" + "0" * 16)
    check("unknown id -> 404", status == 404)

    status, body = req(port, "GET", "/view/" + "0" * 16)
    check("viewer 404 for unknown id", status == 404)

    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    print("\nAll %d checks passed." % PASS)


if __name__ == "__main__":
    main()
