# shh

**A one-time secret bridge for humans and AI agents.**

`shh` keeps plaintext out of chat and model context while a declared receiver or
human claims it once. It is open source, MIT licensed, and self-hostable.

- **Hosted demo:** [shh.qcfailed.com](https://shh.qcfailed.com) — best effort,
  with no account or SLA
- **Agent guide:** [shh.qcfailed.com/agent.md](https://shh.qcfailed.com/agent.md)
- **Source:** [github.com/BDubDesigns/secret-drop](https://github.com/BDubDesigns/secret-drop)
- **Security model:**
  [`docs/architecture-security.md`](docs/architecture-security.md)

The hosted instance is a public demo, not a credential vault, identity provider,
team product, or hosted secrets SaaS. The expected browser implementation
encrypts before upload and gives the relay only opaque ciphertext. Because the
hosted page and relay share an origin, a compromised or malicious operator could
replace the JavaScript and capture a future plaintext before encryption. Self-host
when that trust boundary matters.

## How it works

```text
Human → Agent
agent creates a receiver keypair and public delivery link
        ↓
human opens the complete link and encrypts in the browser
        ↓
relay stores opaque ciphertext; receiver decrypts locally and writes one .env value

Agent → Human
agent reads a value from stdin and publishes ciphertext
        ↓
human opens a one-time reveal link and claims it in the browser
        ↓
browser decrypts locally, removes the capability fragment, and shows the value
```

The receiver private key never enters the delivery link, a request, or normal
output. The reverse reveal link is different: its fragment carries the drop ID
and decryption key, so the link is a live bearer capability until it is claimed.
Keep it private and send it through an appropriate channel.

## Human → Agent quick start

Requires Python 3.12+.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python server.py --port 8899 --ttl 1800
```

In another terminal, request a handoff. The target must be an absolute path whose
basename is `.env`; its parent directory must already exist.

```bash
.venv/bin/python decrypt_to_file.py receive \
  --relay http://127.0.0.1:8899 \
  --name EXPECTED_VARIABLE \
  --target /absolute/path/to/.env
```

For the hosted demo, use `https://shh.qcfailed.com` as the relay origin. The
helper prints a public delivery link. Send the complete clickable URL, including
the fragment after `#`, to the human. The human pastes the value into the browser
and clicks **Encrypt & deliver**. The receiver decrypts locally and prints only a
redacted receipt:

```text
ok: delivered EXPECTED_VARIABLE to the approved target.
```

The value is written atomically with target mode `0600`. It is never printed by
the helper.

## Agent → Human quick start

Read the value from stdin. Never place a literal secret in command-line
arguments, shell history, or normal output.

```bash
# From a file the agent already holds:
cat /path/to/value | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com

# Or from an environment variable:
printf '%s' "$EXPECTED_VARIABLE" | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com
```

The helper prints a one-time reveal link:

```text
shh reveal link: https://shh.qcfailed.com/reveal#<drop_id>.<key>
```

Send that complete link privately to the human. The browser claims and decrypts
it once. After successful decryption, shh removes the key-bearing fragment before
showing the value, offers explicit **Copy secret** and **Hide now** controls, and
clears the display on hide, background/page exit, or after a bounded 120-second
screen/privacy fallback. Copying moves plaintext into the system clipboard,
which is outside shh's control. These are convenience and privacy-hygiene
measures, not a security boundary.

## Deployment and self-hosting

The included Dockerfile declares `/app/data` as its data path and binds the
service for a reverse proxy:

```bash
docker build -t shh .
docker run --rm -p 8899:8899 -v shh-data:/app/data shh
```

For Coolify, add a persistent storage volume at `/app/data`. The image defaults
to not trusting forwarded headers. If a trusted reverse proxy is the immediate
peer, explicitly enable proxy trust and set its CIDR:

```text
--trust-proxy --trusted-proxy-cidr 172.16.0.0/12
```

Use the actual private network for the deployment. Never expose `usage.jsonl` as
a static file or mount it into a public directory.

## Usage telemetry

The server records a local JSONL event with a UTC timestamp, event/status, and a
short-lived keyed-HMAC pseudonym of the client IP. It does not record raw IPs,
secrets, links/fragments, drop IDs, variable names, target paths, request bodies,
ciphertext, or plaintext. Logs are mode `0600` and retained for 14 days. Page
views and routine pending claim polls are not persisted.

This is minimal abuse/usage observation, not access control. A public instance
will receive scanners and unrelated traffic.

## API and public documents

All API responses use `Cache-Control: no-store`. State-changing endpoints require
`Content-Type: application/json`, and the service does not emit permissive CORS
headers.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/drops` | Receiver creates one pending drop. |
| `POST` | `/api/drops/{id}/payload` | Browser submits one versioned sealed-box payload. |
| `POST` | `/api/drops/{id}/claim` | Receiver polls and claims ciphertext once. |
| `GET` | `/api/drops/{id}` | Returns non-secret drop status. |
| `GET` | `/` | Public onboarding or browser sender page. |
| `GET` | `/reveal` | One-time browser reveal page. |
| `GET` | `/agent.md` | Canonical machine-readable agent guide. |
| `GET` | `/llms.txt` | Short agent-discovery document. |
| `GET` | `/healthz` | Liveness check. |

The old `/secret` and `/out/{id}` AES-link endpoints return `410` and are not
compatible with shh v1. Use the supported helper; do not guess or reimplement
the crypto protocol from raw API calls.

## Tests

Install development dependencies and Chromium:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m playwright install chromium
```

Run the full suite:

```bash
.venv/bin/pytest
```

The browser tests prove the actual vendored browser modules encrypt or decrypt
through the relay, preserve one-time semantics, avoid plaintext in helper output
and telemetry, render the public onboarding experience, and exercise the reveal
cleanup controls. Docker CI also verifies the browser flows against the shipped
container rather than an accidental local server.

## Files

- `server.py` — RAM-only relay, pages, public documents, API, rate limits, and telemetry.
- `decrypt_to_file.py` — receiver keypair, polling, release helper, local decryption, and atomic `.env` writer.
- `static/app.js` — browser-side sealed-box encryption and onboarding mode selection.
- `static/app_reveal.js` — one-time reveal, copy/hide controls, and cleanup hygiene.
- `static/app.css` — shared responsive visual system and CSP-compatible styles.
- `docs/agent.md` — canonical agent onboarding instructions.
- `docs/architecture-security.md` — architecture, crypto vocabulary, threat model, and privacy boundary.
- `vendor/` — pinned browser libsodium modules and license texts.

## License

MIT. See `LICENSE`.
