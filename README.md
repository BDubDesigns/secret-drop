# 🔐 Secret Drop

A single-use, end-to-end-encrypted secret sharing box. The whole point: **hand an AI agent a secret without ever pasting it into chat.**

The user pastes a secret in the browser. Web Crypto (AES-GCM) encrypts it **client-side** — the server only ever holds ciphertext and cannot decrypt it. The decryption key rides in the URL fragment (`#...`), which never reaches the server. Each link works **once**, then self-destructs.

## Why this exists

When people discuss "just paste your API key to the agent in chat," that burns the secret — it's logged, stored, and in the model's context. Secret Drop gives a better path: encrypt in the browser → hand the agent a link → agent fetches ciphertext and decrypts to a file. The plaintext never enters chat.

## Security model (why it's safe to host publicly)

- **Server cannot decrypt** — ciphertext only, key lives in the URL fragment.
- **Single-use** — each link serves once, then deletes itself.
- **RAM-only** — nothing touches disk.
- **TTL** — secrets expire after 30 minutes by default.
- **Abuse-hardened** — per-IP POST rate limit, 1 MB payload cap, 50 MB storage ceiling.
- **No bot-blocking** — `robots.txt` allows crawling. Safety comes from single-use + E2E, not from hiding.

## Run it

```bash
python3 server.py --port 8899 --ttl 1800
```

Binds `127.0.0.1` by default — put it behind a reverse proxy (Coolify + Let's Encrypt for production, or a `cloudflared` quick tunnel for testing). Requires `cryptography` for the decrypt helper.

## How it works

**Human side** — paste a secret, click encrypt, copy the link, send the whole link to your agent. The part after `#` is the key; it never touches the server.

**Agent side** — fetch ciphertext, decrypt with the key, write to a file. The value never enters the model's context.

```bash
curl -s "https://BASE/out/{ID}" | jq -r .payload > /tmp/ct.b64
python3 decrypt_to_file.py "https://BASE/{ID}.{KEY}" ~/.secrets/secret
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/secret` | Body `{payload, iv}` (both base64). Returns `{id, ttl}`. |
| `GET` | `/out/{id}` | Fetch ciphertext. Single-use — 404s after first read. |
| `GET` | `/healthz` | Liveness check. |
| `GET` | `/` | The page. |

## Files

- `server.py` — the HTTP server + embedded page.
- `decrypt_to_file.py` — agent-side helper: fetch + decrypt link to a file.

## License

MIT