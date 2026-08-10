# shh — Project Brief

> Working product name: **shh**. Current GitHub repository name remains
> `BDubDesigns/secret-drop` until a deliberate rename decision.

## One-line pitch

**A human can deliver a credential to an approved agent-side destination without
putting its plaintext—or a decryption capability—into chat, model context, or
normal tool output.**

## Why this exists

Pasting an API key into an AI chat burns it into conversation history and model
context. Existing secret managers often let an agent read a secret value, while
generic one-time secret sharing gives the recipient a bearer decryption link.

`shh` is deliberately narrower: safe **secret ingress** for an agent workflow.
It gets a human-provided value into a declared destination silently. It is not a
vault and it is not a general-purpose agent credential broker.

## Product decision: scope of v1

Build **transcript-safe encrypted delivery**, not hostile-agent containment.

For the expected, unmodified implementation, `shh` protects against:

- plaintext in chat history or model context;
- plaintext in normal tool output / helper stdout or stderr;
- a hosted relay reading the ciphertext as if it were plaintext;
- ordinary persistent relay storage of plaintext.

`shh` does **not** claim to protect a secret after delivery from a malicious
agent, malware, or any process with the same OS-level access to the destination.
If a secret is written to `.env`, an agent with unrestricted filesystem access
can read it. Stronger containment requires a separately isolated,
operation-scoped credential broker and is explicitly out of scope for v1.

### Personal-use milestone trust boundary

The first implementation is for Brandon's own Hermes handoffs. It uses one
same-origin service for the browser page and relay, with no account or
authentication gate. This keeps deployment cheap and preserves the important
transcript-safe property, but it adds one explicit limitation: a compromised
relay that can replace the page's JavaScript can capture a new plaintext before
encryption. A future stronger deployment can split the static sender page from
the relay origin; that is not required for this personal-use milestone.

The unauthenticated endpoint is expected to receive scanners and unrelated
traffic. Per-client rate limits and short-lived, keyed-HMAC IP telemetry are
for abuse/usage observation only; they are not access control. Raw client IPs,
request bodies, URLs/fragments, drop IDs, target paths, variable names, keys,
ciphertext, and plaintext are not logged.

## The key v1 improvement over the existing prototype

The current prototype encrypts with a symmetric AES key embedded in the shared
one-time URL. That keeps plaintext out of chat but puts a temporary decryption
capability in the transcript.

The v1 product must instead use a **receiver-owned ephemeral keypair**:

1. A local `shh receive` helper creates a one-time receiver keypair and retains
   the private key locally.
2. It returns only a drop ID plus the *public* encryption key as a user-facing
   URL or QR code. That information is safe to show in chat.
3. The browser encrypts the human's secret to the receiver public key before
   upload.
4. The relay stores only encrypted ciphertext.
5. The receiver retrieves and decrypts the ciphertext, then writes it to the
   declared target without emitting the plaintext.
6. The agent sees only a receipt, for example:
   `Delivered GITHUB_TOKEN to approved target.`

Use vetted cryptographic primitives/libraries. Do **not** hand-roll encryption,
key exchange, serialization, or randomness.

## Intended happy path

```text
Agent requests: GITHUB_TOKEN → /workspace/my-app/.env
        ↓
shh receiver creates an ephemeral keypair and a public delivery link/QR
        ↓
Human opens link and pastes the credential in their browser
        ↓
Browser encrypts to receiver public key; relay stores ciphertext once
        ↓
Receiver decrypts locally and atomically writes GITHUB_TOKEN=…
        ↓
Agent receives a redacted success receipt only
```

## Required v1 behavior / acceptance criteria

### Delivery and UX

- A receiver can request one environment variable into a declared `.env` target.
- The target path and variable name are fixed before the human enters a value.
- The browser works without an account for a one-time drop.
- A drop expires after a short TTL and is destroyed after a successful claim.
- A receiver reports status and delivery success without printing the value.
- The writing path is atomic and preserves a valid `.env` file.

### Security invariants

- Plaintext is never sent to the relay when the expected browser code is served.
- The receiver private key is never put in a chat-visible URL, normal tool
  response, or relay request.
- Browser-facing URLs contain no secret-equivalent decryption capability.
- No raw secret may be printed, logged, placed in an exception, or returned by
  a command's stdout/stderr.
- Decryption occurs only in the receiver helper.
- The helper accepts only declared target types/paths; do not create a generic
  arbitrary-write primitive.
- Client and relay responses use `Cache-Control: no-store`.
- Bound input size, short TTL, one-time claim semantics, bounded storage, and
  per-IP creation rate limiting remain in place.
- Usage telemetry is local, access-restricted, pseudonymous, and retained only
  for a short operational window.

### Quality / verification

- Unit tests cover encryption envelope parsing, malformed input, expiry,
  single-use behavior, and `.env` writing.
- End-to-end tests prove: encrypted browser-compatible payload → relay → local
  receiver → expected target, then second claim is rejected.
- Tests assert that the test secret does not appear in captured helper stdout
  or stderr.
- Documentation includes a threat-model section with the explicit v1 boundary.
- README has a copy-paste local quick start and deployment path.

## Explicitly out of scope for v1

- A generic `get_secret` / secret-listing endpoint.
- An MCP tool whose argument is the raw secret.
- Generic arbitrary command execution with a secret.
- Claiming protection against a fully privileged or malicious local agent.
- A full secret vault, identity provider, team sharing, billing, or OAuth
  credential broker.

## Technical constraints and starting point

- Existing prototype is Python stdlib HTTP plus a Python crypto dependency in
  `server.py` and `decrypt_to_file.py`; v1 uses PyNaCl/libsodium sealed boxes.
- Existing public repository: https://github.com/BDubDesigns/secret-drop
- Existing behavior already has RAM-only storage, one-time claims, TTL,
  bounded payload/storage, creation rate limiting, and `no-store` headers.
- Preserve the low-cost, easy-to-self-host character. Prefer a small, auditable
  implementation over a dependency-heavy platform.
- The hosted relay must run correctly behind a reverse proxy / Coolify.

## Delivery process

Use the Terra/Luna loop for all substantive changes:

1. **Terra plans** against this brief, real repository state, and acceptance
   criteria. The plan must identify files, tests, security risks, migration
   from the existing symmetric-link format, and a rollback path.
2. **Luna implements** only an approved plan, in a feature branch.
3. **Terra reviews actual diffs and test results**, not an implementation
   summary.
4. **Luna fixes** Terra's findings and repeats review until approved.
5. Do not claim completion until tests pass and Terra approves the actual diff.

Keep one issue, one active branch, and one active PR. Never auto-merge.

## Future direction (not current scope)

A separate, later `shh broker` could grant agents narrowly scoped operations
("deploy this project") without revealing a credential. It would need actual
isolation and policy enforcement. Treat that as a new project decision, not a
quiet extension of v1.
