# shh agent guide

`shh` is an open-source, MIT-licensed, self-hostable, one-time secret bridge
between humans and AI agents. The hosted instance at
`https://shh.qcfailed.com` is a best-effort public demo with no account, SLA, or
identity guarantee. Use it only when that posture is acceptable; serious
installations can self-host.

## Safety rules

- Never ask a human to paste a secret into chat or model context. Give them the
  complete clickable handoff URL instead.
- Never pass a literal secret through command-line arguments. Command arguments
  can be visible to shell history, `/proc`, process supervisors, and logs.
- Use the supported helper below. Do not guess or reimplement the cryptographic
  protocol from raw HTTP API calls.
- The expected browser implementation encrypts in the client. The relay receives
  opaque ciphertext, but the same-origin operator serves the JavaScript and could
  replace it to capture a future plaintext before encryption. This is not a
  hostile-operator-resistant vault.
- Short TTLs, rate limits, storage ceilings, and one-time claims control abuse and
  lifecycle. They are not identity or access control.

## Human → Agent: receive a value

Clone the repository or use an approved local checkout. Python 3.12+ and the
runtime requirements are required:

```bash
git clone https://github.com/BDubDesigns/secret-drop.git
cd secret-drop
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Choose the expected variable name and an absolute `.env` target whose parent
already exists. Ask the helper to create the handoff and keep it running:

```bash
.venv/bin/python decrypt_to_file.py receive \
  --relay https://shh.qcfailed.com \
  --name EXPECTED_VARIABLE \
  --target /absolute/path/to/.env
```

The helper prints a public-key-only URL similar to:

```text
shh link: https://shh.qcfailed.com/#<drop_id>.<public_key>
```

Send the complete clickable URL, including everything after `#`, to the human.
The human encrypts in their browser. The relay stores only ciphertext; the
helper decrypts locally and writes the declared variable to the approved `.env`
file. A successful helper receipt is:

```text
ok: delivered EXPECTED_VARIABLE to the approved target.
```

The helper never prints the delivered value.

## Agent → Human: release a value

Read the value from stdin. Use a file the agent already holds:

```bash
cat /path/to/value | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com
```

Or use an environment variable without putting the value in the command line:

```bash
printf '%s' "$EXPECTED_VARIABLE" | .venv/bin/python decrypt_to_file.py release \
  --relay https://shh.qcfailed.com
```

On confirmed publish, the helper prints:

```text
shh reveal link: https://shh.qcfailed.com/reveal#<drop_id>.<key>
```

Send that complete clickable reveal URL privately to the human. It is a live
bearer capability until claimed: anyone with it may claim the one-time value.
The browser decrypts locally. After successful decryption it removes the key
fragment from the address bar, offers explicit Copy secret and Hide now controls,
and clears the display when hidden or exited, with a bounded 120-second fallback.
Copying moves plaintext into the system clipboard, which is outside `shh`'s
control. These actions are privacy hygiene, not a security boundary.

If upload confirmation is ambiguous, the helper may print a recovery reveal link
and exit with code 4. Treat that link as potentially live and handle it privately.

## Exit codes

| Command | Code | Meaning |
|---|---:|---|
| `receive` | 0 | Value decrypted and written to the approved target. |
| `receive` | 2 | Input validation failed. |
| `receive` | 3 | Relay failure or invalid relay response. |
| `receive` | 4 | Drop expired or became unavailable. |
| `receive` | 5 | Delivered payload could not be decrypted. |
| `receive` | 6 | Target or value validation failed. |
| `release` | 0 | Ciphertext published and link confirmed. |
| `release` | 2 | Input validation failed. |
| `release` | 3 | Relay rejected the publish or could not complete it. |
| `release` | 4 | Upload confirmation was ambiguous; a recovery link was preserved. |

## Trust and source links

- Product README: https://github.com/BDubDesigns/secret-drop/blob/main/README.md
- Architecture and security: https://github.com/BDubDesigns/secret-drop/blob/main/docs/architecture-security.md
- Self-hosting and deployment: https://github.com/BDubDesigns/secret-drop#deployment
- Source repository: https://github.com/BDubDesigns/secret-drop

Use the supported helper. Never ask a human to paste a secret into chat, never
put a literal secret in argv, and never claim that a hosted relay operator cannot
change the JavaScript it serves.
