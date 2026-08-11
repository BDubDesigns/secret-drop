# shh

`shh` is a small, self-hostable secret-ingress tool for Brandon's Hermes
handoffs. It moves one human-provided environment variable into one declared
`.env` file without putting the plaintext in Discord, model context, normal tool
output, or relay storage.

This milestone is for personal use. It has no accounts and no authentication
wall. It is rate-limited and will still receive scanners and random traffic
when exposed to the internet.

## How it works

```text
receiver helper creates a one-time keypair
        ↓ public key only in a delivery URL fragment
human opens the link and pastes a secret
        ↓ libsodium sealed box in the browser
relay stores opaque ciphertext in RAM
        ↓ one-time claim
receiver decrypts locally and atomically writes one .env variable
```

The receiver private key never enters the link, a request, or normal output.
The browser uses the receiver public key with libsodium's `crypto_box_seal`.
The relay cannot decrypt ciphertext under the expected page implementation.

### Important trust boundary

This personal-use deployment serves the browser page and relay from the same
origin. A compromised relay could replace the JavaScript page and capture a new
plaintext before encryption. That is intentionally a narrower claim than a
separate sender origin; see [`docs/architecture-security.md`](docs/architecture-security.md).

## Local quick start

Requires Python 3.12+.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python server.py --port 8899 --ttl 1800
```

In another terminal, request a handoff. The target must be an absolute path
whose basename is `.env`; its parent directory must already exist.

```bash
.venv/bin/python decrypt_to_file.py receive \
  --relay http://127.0.0.1:8899 \
  --name GITHUB_TOKEN \
  --target /absolute/path/to/.env
```

The helper prints a public delivery link. Open it in a browser, paste the
credential, and click **Encrypt & deliver**. The helper prints only:

```text
ok: delivered GITHUB_TOKEN to the approved target.
```

The value is written atomically with target mode `0600`. It is never printed by the helper.
Values accepted by `shh` load exactly under normal python-dotenv/Hermes semantics:
ordinary `$`, backticks, backslashes, and quotes round-trip. NULs, multiline
values, and `${...}` interpolation syntax are rejected rather than transformed.

### Reverse handoff: agent → human (`release`)

To hand a secret **back out** to a human without putting plaintext in chat,
publish it for a one-time browser reveal. Read the value from stdin — never
embed the literal in the command line (argv leaks via `/proc/*/cmdline`, shell
history, and process supervisors):

```bash
# From a file the agent already holds:
cat /path/to/secret | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com

# Or from an environment variable (no literal in argv):
printf '%s' "$SECRET_VAR" | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com
```

The helper encrypts the value with a fresh symmetric key, submits only
ciphertext to the relay, and prints a single-use reveal link:

```text
shh reveal link: https://shh.qcfailed.com/reveal#<drop_id>.<key>
```

Open the reveal link in a browser, click **Reveal secret**, and the value is
decrypted locally and shown once, then auto-clipped after a few seconds. The
fragment carries both the drop id and the key, so the link is the capability:
treat it as live until it is claimed. After a single claim the relay deletes
the ciphertext, so a recovered key later cannot decrypt anything.

## Deployment

The included Dockerfile declares `/app/data` as its data path, writes telemetry
there by default, and binds the service for a reverse proxy:

```bash
docker build -t shh .
docker run --rm -p 8899:8899 -v shh-data:/app/data shh
```

For Coolify, add a **Persistent Storage** volume with a descriptive name (for
example `shh-data`) and destination path `/app/data`. Coolify namespaces the
volume for the resource and keeps it across deployments. Dockerfile `VOLUME`
metadata establishes the portable default path, but it does not create or
manage Coolify's resource-level persistent-volume setting.

The image defaults to not trusting forwarded headers. If Coolify is the
immediate proxy, explicitly enable proxy trust and set the CIDR of the proxy
network, for example:

```text
--trust-proxy --trusted-proxy-cidr 172.16.0.0/12
```

Use the actual private network for your deployment. The proxy must strip and
set `X-Forwarded-For`; do not enable this flag when clients can connect
directly or when the proxy merely appends untrusted values.

Never expose `usage.jsonl` as a static file or mount it into a public directory.
The file contains pseudonymous client identifiers and operational events.

## Usage telemetry

The server records a local JSONL event with:

- UTC timestamp;
- event and status;
- a short-lived keyed-HMAC pseudonym of the client IP.

It does not record raw IPs, secrets, links/fragments, drop IDs, variable names,
target paths, request bodies, ciphertext, or plaintext. Logs are mode `0600`
and retained for 14 days. Normal records are append-only; bounded retention
maintenance runs at startup and through the existing periodic sweeper. The page
discloses this telemetry. Page views and routine pending claim polls are not
persisted.

This is minimal abuse/usage observation, not access control. If you expose the
service publicly, expect unrelated traffic and rate-limit responses.

## API

All API responses use `Cache-Control: no-store`.
State-changing endpoints require `Content-Type: application/json` (normal
parameters such as `charset=utf-8` are accepted). Other media types receive
`415 unsupported_media_type` before rate-limit or drop-state mutation. The
service does not emit permissive CORS headers.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/drops` | Receiver creates one pending drop. |
| `POST` | `/api/drops/{id}/payload` | Browser submits one versioned base64url sealed-box payload. |
| `POST` | `/api/drops/{id}/claim` | Receiver polls and atomically claims ciphertext once. |
| `GET` | `/api/drops/{id}` | Returns non-secret pending/submitted/claimed status. |
| `GET` | `/healthz` | Liveness check. |
| `GET` | `/` | Browser sender page. |

The old `/secret` and `/out/{id}` AES-link endpoints return `410` and are not
compatible with shh v1.

## Tests

Install development dependencies:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m playwright install chromium
```

Run unit tests plus the real browser-to-receiver delivery test:

```bash
.venv/bin/pytest
```

The browser test proves that the actual vendored browser modules encrypt a
secret, the relay receives only ciphertext, the receiver decrypts it locally,
and the expected `.env` file is written. It also asserts that the test secret
is absent from captured helper stdout and stderr.

On stripped ARM64 containers, Chromium may need local shared libraries. The
application itself does not need those test-only libraries; install them using
your image's normal package mechanism or set `LD_LIBRARY_PATH` for the test
process only.

## Files

- `server.py` — RAM-only relay, browser page, API, rate limits, and telemetry.
- `decrypt_to_file.py` — receiver keypair, polling, sealed-box decryption, and
  atomic `.env` writer.
- `static/app.js` — browser-side sealed-box encryption.
- `vendor/` — pinned browser libsodium modules and license texts.
- `docs/architecture-security.md` — architecture, crypto vocabulary, threat
  model, privacy policy, lifecycle, and rollback notes.
- `docs/THIRD_PARTY_NOTICES.md` — dependency/license provenance.

## License

MIT. See `LICENSE`.
