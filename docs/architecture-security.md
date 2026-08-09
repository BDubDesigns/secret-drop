# shh personal-use architecture and security

## What this is for

`shh` is a narrow secret-ingress tool for one workflow:

```text
Brandon requests GITHUB_TOKEN -> an approved .env target
        |
        v
receiver creates a one-time keypair and prints a public delivery link
        |
        v
human opens the link and pastes the token in a browser
        |
        v
browser encrypts to the receiver public key and uploads ciphertext
        |
        v
receiver claims ciphertext, decrypts locally, and atomically updates .env
        |
        v
Hermes sees only a redacted delivery receipt
```

It is not a vault, identity provider, credential broker, or general file-write
primitive.

## Components and trust boundaries

The personal-use milestone has one HTTP origin:

```text
same origin
+------------------------------+
| static browser page          |
| /api/drops relay             |
| RAM-only ciphertext storage  |
| local usage telemetry file   |
+------------------------------+
```

The receiver helper runs locally and is the only component that holds the
private key or plaintext. The relay has an opaque payload and no decryption
endpoint.

This same-origin choice is deliberate and limited. It protects against a
normal relay operator or storage system reading ciphertext as plaintext, but it
does **not** protect against a compromised relay serving altered JavaScript. An
altered page could copy a new plaintext before the browser encrypts it. A future
stronger deployment can serve the static sender page from a separately secured
origin; that is a deployment change, not a crypto-protocol change.

There is no account or authentication gate in this milestone. The service is
expected to receive scanners and unrelated traffic. Rate limiting is an abuse
control, not access control.

## Key lifecycle, in plain English

1. `decrypt_to_file.py receive` validates the variable name and `.env` target.
2. It creates a fresh X25519 receiver keypair in process memory using PyNaCl.
3. It sends an empty create request to the relay. The relay returns a random
   drop ID.
4. The helper prints a URL whose fragment contains the drop ID and receiver
   **public** key. The private key never enters the URL, request, stdout, or
   relay.
5. The browser reads the fragment locally. Browsers do not send URL fragments
   in HTTP requests.
6. The browser calls `crypto_box_seal` through `libsodium-wrappers` to encrypt
   the plaintext to the receiver public key.
7. The browser posts only a version number and base64url ciphertext to the
   relay. The relay stores the opaque bytes in RAM.
8. The helper polls the claim endpoint. The first successful claim removes the
   payload from storage and returns it once.
9. PyNaCl's `SealedBox` opens the ciphertext locally with the private key.
10. The helper validates the one-line UTF-8 value and atomically replaces the
    declared `.env` file using a temporary file, `fsync`, and `os.replace`.
11. The helper prints only a redacted receipt such as:

    ```text
    ok: delivered GITHUB_TOKEN to the approved target.
    ```

The private key is held only in the receiver process. If that process dies
before the claim, the drop expires. If it dies after claiming but before the
file write, the one-time payload is intentionally gone and the handoff must be
restarted.

## Crypto vocabulary and why these libraries exist

The implementation uses the vetted sealed-box primitive rather than combining
lower-level primitives by hand.

- **X25519 / Curve25519** is the elliptic-curve key agreement mechanism. It
  lets the ephemeral browser sender derive a shared secret with the receiver
  public key without learning the receiver private key.
- **`crypto_box_seal`** creates a fresh ephemeral sender key internally,
  performs the key agreement, and serializes the result into the ciphertext.
  The recipient can open it with the receiver private key.
- **XSalsa20-Poly1305** is the authenticated encryption construction used by
  libsodium's sealed boxes. XSalsa20 provides confidentiality; Poly1305
  authenticates the ciphertext so modification is detected.
- **PyNaCl** is the Python binding used by the receiver. Its `SealedBox` API
  calls libsodium rather than implementing the primitive in Python.
- **`libsodium`** is the vendored browser cryptographic implementation.
  **`libsodium-wrappers`** exposes its API to the browser module.

The browser and receiver both use the same libsodium sealed-box format. There
is no custom KDF, nonce format, key serialization scheme, or encryption envelope
in this repository.

## Relay state machine

A drop begins as `pending` and contains no payload. The browser can submit one
payload, moving it to `submitted`. The first receiver claim returns the opaque
payload, clears its bytes, and marks the metadata `claimed`. The sweeper removes
expired metadata. A second claim receives only `404 not_found`.

The relay enforces:

- short default TTL (30 minutes);
- 1 MB maximum ciphertext payload;
- 50 MB total ciphertext storage ceiling;
- bounded active-drop count;
- per-client creation/submission limits;
- a higher claim polling budget so a normal receiver can poll;
- `Cache-Control: no-store` and defensive response headers.

The relay validates the base64url envelope and version but never decrypts or
interprets the payload bytes.

## Target writer boundary

The helper does not accept an arbitrary path or command. It accepts one
absolute path whose basename is exactly `.env`, and one environment variable
matching:

```text
[A-Za-z_][A-Za-z0-9_]*
```

The parent directory must already exist. Existing symlink targets, directories,
non-UTF-8 files, duplicate assignments, NULs, and multiline values are
rejected. Unrelated `.env` lines and comments are preserved. The target file is
always written with mode `0600`.

The writer replaces one assignment with a conservative quoted value. It writes
to a same-directory temporary file, flushes and fsyncs it, atomically renames
it, then fsyncs the directory. A crash yields either the old complete file or
the new complete file, not a partially written file.

## Usage telemetry and privacy

The service records a local JSONL event for page visits, drop creation,
payload submission, claim outcomes, and rate limiting. Each event contains only:

```json
{"ts":"2026-01-01T12:00:00Z","event":"page","ip_tag":"…","status":"ok"}
```

`ip_tag` is the first 16 bytes of HMAC-SHA256 over the client IP with a random
process-local key. The key is regenerated on restart, so the pseudonym is not a
stable cross-restart identifier. The raw IP is not written to the usage log.
Logs are local, mode `0600`, and pruned after 14 days. The page discloses this
telemetry.

When deployed behind a reverse proxy, forwarded client IPs are accepted only
when proxy trust is explicitly enabled and the immediate peer belongs to an
operator-configured trusted proxy CIDR. The proxy must strip and set the
forwarded header; the default container configuration does not trust it. This
prevents a direct client from spoofing an address to bypass rate limits or
poison telemetry.

This is operational telemetry, not user tracking. It is still personal-data
handling in many jurisdictions, which is why the implementation minimizes the
value, retention, and visibility of the identifier. If this becomes a service
for other people, add a real privacy policy and revisit the retention period
with legal advice rather than silently expanding collection.

The following must never appear in usage logs, server logs, helper stdout or
stderr, test output, exceptions, commits, or documentation:

- plaintext secrets;
- receiver private keys;
- URL fragments or full handoff links;
- drop IDs, variable names, or target paths;
- request bodies or ciphertext;
- decryption errors containing input data.

## What this protects and does not protect

| Situation | Protected? | Reason |
|---|---:|---|
| Secret pasted into Discord/model context | Yes | The human sends a public-key link, not the plaintext. |
| Relay stores ciphertext on disk by accident | Yes, for ciphertext confidentiality | The relay never receives the plaintext or private key. |
| Normal server request logs | Yes | Request logging is suppressed and URL fragments are client-only. |
| Passive network observer | Yes, with HTTPS | The link and ciphertext need transport confidentiality. |
| Random scanner submits junk | Bounded | Size limits, TTL, RAM ceiling, and rate limits apply. |
| Compromised same-origin relay serves malicious JavaScript | No | The page can read a new plaintext before encryption. |
| Malicious local agent after delivery | No | The target `.env` is intentionally available to local processes with access. |
| Host compromise that reads receiver process memory | No | The private key and decrypted value exist in receiver memory briefly. |
| User sends the link without the complete fragment | No | The receiver must restart the one-time handoff. |

## Rollback and compatibility

The old AES key-in-link prototype is not compatible with this protocol. Old
links are intentionally rejected with `410 legacy_endpoint_removed` rather than
silently attempting ambiguous decryption. If the v1 branch must be rolled back,
redeploy the previous known-good commit and treat any links created by the new
protocol as invalid. Never mix old and new payload formats in one endpoint.

## Dependencies and provenance

- Python runtime: `PyNaCl==1.6.0`.
- Browser runtime: `libsodium==0.8.4` and `libsodium-wrappers==0.8.4`, vendored
  under `vendor/` and served from the same origin.
- The exact third-party license texts are in `vendor/` and summarized in
  `docs/THIRD_PARTY_NOTICES.md`.
