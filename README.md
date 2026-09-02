# OpenCert API

A tiny, dependency-free API (Python 3 stdlib only) that accepts an OpenCert file,
validates and hosts it, and returns a link that opens the certificate in the
OpenCert viewer at `https://www.opencerts.io/`.

## Run

```sh
python3 server.py            # listens on :8080
```

## API

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/api/certificates` | Upload an OpenCert — a multipart form-data file part (any name, `file` preferred) or a raw `application/json` body |
| `GET` | `/api/certificates` | List stored certificates |
| `GET` | `/api/certificates/<id>` | Fetch a certificate as JSON (this is the stable URL the viewer fetches) |
| `GET` | `/view/<id>` | Open the certificate in a built-in viewer (for local testing) |
| `GET` | `/` | API docs |

### Upload example

```sh
curl -F "file=@examples/sample.opencert.json" http://localhost:8080/api/certificates
```

```json
{
  "id": "0a1b2c3d4e5f6a7b",
  "name": "Alice Nguyen",
  "url": "http://localhost:8080/api/certificates/0a1b2c3d4e5f6a7b",
  "viewerUrl": "https://www.opencerts.io/http%3A%2F%2Flocalhost%3A8080%2Fapi%2Fcertificates%2F0a1b2c3d4e5f6a7b",
  "created": true
}
```

`url` is the stable hosted copy of the certificate. `viewerUrl` is where to
open it — by default it points at `https://www.opencerts.io/` with the hosted
`url` URL-encoded and appended, so the viewer fetches the certificate from this
API.

### Changing the viewer URL

To open certificates in a different viewer, set `OPENCERT_VIEWER_URL` to the
part of the viewer URL that precedes the certificate URL:

```sh
OPENCERT_VIEWER_URL="https://viewer.example.com/?cert=" python3 server.py
```

Then `viewerUrl` becomes
`https://viewer.example.com/?cert=http%3A%2F%2Flocalhost%3A8080%2Fapi%2Fcertificates%2F<id>`.

## Configuration

| Env var | Default | Purpose |
| ------- | ------- | ------- |
| `PORT` | `8080` | Listen port |
| `HOST` | `0.0.0.0` | Bind address |
| `CERT_DATA_DIR` | `./data/certificates` | Where certificates are stored (JSON files) |
| `OPENCERT_VIEWER_URL` | `https://www.opencerts.io/` | Base URL of the OpenCert viewer; the hosted certificate URL is appended |

## Validation

Uploads must be a JSON object in one of the two OpenCert shapes seen in the wild:

- **OpenAttestation documents** (e.g. NTU PACE certificates from
  `render.ntu.edu.sg`) — a `data` object plus `version`/`schema`/`signature`/`proof`
- **W3C VerifiableCredentials** — `@context` plus `credentialSubject` (or a nested `credential`)

Encoded field values (`<uuid>:string:Name`) are decoded for display and for the
`name` in responses. Unrecognized documents return `400` with a `details` list.

## Tests

```sh
python3 test_api.py
```
