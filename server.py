#!/usr/bin/env python3
"""
secret-drop -- a Yopass-style single-use secret drop box.

The user pastes a secret in the browser. Web Crypto (AES-GCM) encrypts it
client-side in the browser; the server only ever sees/stores ciphertext (the
"server cannot decrypt" property). The decryption key rides in the URL fragment
(#...) which never reaches the server.

The server is RAM-only, single-use: a secret is deleted after first read (or
after a TTL). Fetching a secret requires the random one-time ID (the "code").

Agent side: the agent fetches `GET /out/<id>` with curl into a file, then
decrypts with the key from the URL fragment using a helper script -- so the
plaintext never enters the agent's context/transcript.

Hardening (production-safe for public/anonymous hosting):
  - Per-IP POST rate limiting (token bucket) -- prevents abuse floods.
  - Payload size cap -- a single secret can't exceed MAX_PAYLOAD_BYTES.
  - Storage ceiling -- total ciphertext bytes are bounded so an abuse spike
    can't OOM the box.
  - Short default TTL + a background sweeper for expired secrets.
  - `Cache-Control: no-store` on every response.
  - robots.txt ALLOWS crawling -- agents must be able to discover the tool.
    (Safety comes from single-use + E2E encryption, NOT from blocking bots.)

Run:
    python3 server.py --port 8899 --ttl 1800
Serve the dir behind a reverse proxy (Coolify / Let's Encrypt, or a cloudflared
quick tunnel for testing). Bind 127.0.0.1 by default -- keep it behind the proxy.
"""

import argparse
import base64
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Tunables (hardening knobs)
# ---------------------------------------------------------------------------
DEFAULT_TTL_SECONDS = 1800.0          # 30 min default lifetime
MAX_PAYLOAD_BYTES = 1_000_000         # 1 MB max per secret (ciphertext+iv)
MAX_TOTAL_BYTES = 50_000_000          # 50 MB total storage ceiling
MAX_POSTS_PER_MINUTE = 10             # per-IP POST rate limit
SWEEP_INTERVAL_SECONDS = 30.0

# ---------------------------------------------------------------------------
# Storage: dict of id -> {payload, iv, created, ttl}. RAM only. Never touches disk.
# ---------------------------------------------------------------------------
STORE: dict[str, dict] = {}
STORE_LOCK = threading.Lock()
TOTAL_BYTES = 0

# Per-IP POST rate limiting: dict of ip -> list[timestamps] (rolling window).
# Accessed under STORE_LOCK.
POST_HISTORY: dict[str, list[float]] = {}


def _now() -> float:
    return time.time()


def _exceeds_post_rate(ip: str) -> bool:
    """Return True if this IP has posted more than MAX_POSTS_PER_MINUTE recently."""
    with STORE_LOCK:
        now = _now()
        window = now - 60.0
        recent = [t for t in POST_HISTORY.get(ip, []) if t > window]
        POST_HISTORY[ip] = recent
        if len(recent) >= MAX_POSTS_PER_MINUTE:
            return True
        recent.append(now)
        POST_HISTORY[ip] = recent
        return False


def _store_secret(payload_b64: str, iv_b64: str, ttl: float) -> tuple[str | None, str | None]:
    """Store a secret. Returns (id, error). error is None on success."""
    global TOTAL_BYTES
    size = len(payload_b64) + len(iv_b64)
    with STORE_LOCK:
        if TOTAL_BYTES + size > MAX_TOTAL_BYTES:
            return None, "storage_full"
        secret_id = secrets.token_urlsafe(18)
        STORE[secret_id] = {
            "payload": payload_b64,
            "iv": iv_b64,
            "created": _now(),
            "ttl": ttl,
        }
        TOTAL_BYTES += size
    return secret_id, None


def _take_secret(secret_id: str) -> dict | None:
    """Return the secret and DELETE it (single-use). None if missing/expired."""
    global TOTAL_BYTES
    with STORE_LOCK:
        item = STORE.pop(secret_id, None)
        if item is None:
            return None
        TOTAL_BYTES -= len(item["payload"]) + len(item["iv"])
        TOTAL_BYTES = max(0, TOTAL_BYTES)
        if _now() - item["created"] > item["ttl"]:
            return None  # expired; already removed
        return item


def _sweep_expired(ttl_floor: float) -> None:
    global TOTAL_BYTES
    with STORE_LOCK:
        now = _now()
        for sid in [s for s, v in STORE.items() if now - v["created"] > v["ttl"]]:
            item = STORE.pop(sid, None)
            if item:
                TOTAL_BYTES -= len(item["payload"]) + len(item["iv"])
        TOTAL_BYTES = max(0, TOTAL_BYTES)


# ---------------------------------------------------------------------------
# The page (embedded HTML with usage instructions for humans AND agents)
# ---------------------------------------------------------------------------
def _build_page(ttl_seconds: float) -> str:
    ttl_min = int(ttl_seconds // 60)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secret Drop — single-use secret sharing</title>
<meta name="description" content="Send a secret to an AI agent without ever pasting it in chat. Browser-side AES-GCM encryption, single-use links, server can't decrypt.">
<style>
  body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;max-width:620px;margin:40px auto;padding:0 20px;line-height:1.6}}
  h1{{font-size:1.5rem}} h2{{font-size:1.1rem;margin-top:28px}}
  textarea{{width:100%;height:140px;background:#1a1d24;color:#e6e6e6;border:1px solid #333;border-radius:8px;padding:10px;font-family:ui-monospace,monospace;box-sizing:border-box}}
  button{{margin-top:12px;padding:10px 18px;border:0;border-radius:8px;background:#4f8cff;color:#fff;font-size:1rem;cursor:pointer}}
  button:disabled{{opacity:.5}}
  #result{{margin-top:16px;white-space:pre-wrap;word-break:break-all;background:#1a1d24;padding:12px;border-radius:8px;display:none}}
  .note{{font-size:.85rem;color:#9aa;margin-top:24px;line-height:1.6}}
  code,pre{{background:#1a1d24;padding:1px 5px;border-radius:4px;font-family:ui-monospace,monospace}}
  pre{{padding:10px;overflow-x:auto}}
  .alert{{background:#2a1f1f;border:1px solid #5a3a3a;padding:10px 14px;border-radius:8px;margin-top:20px;font-size:.9rem}}
</style></head><body>
<h1>🔐 Secret Drop</h1>
<p>Paste your secret below. It is <b>encrypted in your browser</b> (AES-GCM) before it leaves your machine. The server stores only ciphertext and deletes it after first read (or {ttl_min} min).</p>

<h2>Create a secret</h2>
<textarea id="input" placeholder="Paste the secret here..."></textarea><br>
<button id="go">Encrypt &amp; create link</button>
<div id="result"></div>

<h2>How to use it</h2>
<p><b>For a human:</b> paste your secret above, click encrypt, copy the link, and send the <i>whole link</i> to your agent. The part after <code>#</code> is the decryption key — it never touches the server. The link works once and then self-destructs.</p>
<p><b>For an AI agent (the part after the <code>#</code> is the key):</b></p>
<pre>curl -s "https://BASE_URL/out/&#123;ID&#125;" \
  | jq -r .payload > /tmp/ct.b64
# then decrypt /tmp/ct.b64 with the key from the URL fragment
python3 decrypt_to_file.py "https://BASE_URL/&#123;ID&#125;.&#123;KEY&#125;" ~/.secrets/secret</pre>
<p>The agent fetches the ciphertext, decrypts with the key, and writes the plaintext to a file — the secret value <b>never enters the chat transcript</b>.</p>

<div class="alert"><b>Security note:</b> this is a public, anonymous tool. Links are single-use and self-destruct after first read. The server cannot decrypt your secret — it only ever holds ciphertext, and the key never leaves the recipient's browser. Never use this for anything you wouldn't trust to a public URL.</div>

<script>
const enc = new TextEncoder();
async function encrypt(plain) {{
  const key = await crypto.subtle.generateKey({{name:"AES-GCM",length:256}}, true, ["encrypt","decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({{name:"AES-GCM",iv}}, key, enc.encode(plain));
  const raw = await crypto.subtle.exportKey("raw", key);
  const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
  return {{ct: b64(ct), iv: b64(iv), key: b64(raw)}};
}}
document.getElementById("go").onclick = async () => {{
  const plain = document.getElementById("input").value;
  if(!plain){{alert("Paste a secret first.");return;}}
  const btn = document.getElementById("go"); btn.disabled = true;
  try {{
    const {{ct, iv, key}} = await encrypt(plain);
    const r = await fetch("/secret", {{method:"POST", headers:{{"Content-Type":"application/json"}},
      body: JSON.stringify({{payload: ct, iv}})}});
    const j = await r.json();
    const link = location.href.split("#")[0] + "#" + j.id + "." + key;
    const out = document.getElementById("result");
    out.style.display = "block";
    out.textContent = link;
    out.onclick = () => {{ navigator.clipboard.writeText(link); }};
  }} finally {{ btn.disabled = false; }}
}};
</script></body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class DropHandler(BaseHTTPRequestHandler):
    secret_ttl: float = DEFAULT_TTL_SECONDS

    def log_message(self, fmt, *args):
        pass  # keep console noise low

    def _client_ip(self) -> str:
        # Respect X-Forwarded-For when behind a proxy (Coolify/tunnel).
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._send(200, _build_page(self.secret_ttl).encode(), "text/html; charset=utf-8")
            return
        if path == "/robots.txt":
            # Allow crawling -- agents must be able to discover the tool.
            self._send(200, b"User-agent: *\nAllow: /\n", "text/plain")
            return
        if path == "/healthz":
            self._json({"status": "ok"})
            return
        if path.startswith("/out/"):
            secret_id = path[len("/out/"):]
            item = _take_secret(secret_id)
            if item is None:
                self._json({"error": "not_found"}, 404)
                return
            self._json({"payload": item["payload"], "iv": item["iv"]})
            return
        self._json({"error": "not_found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/secret":
            self._json({"error": "not_found"}, 404)
            return

        ip = self._client_ip()
        if _exceeds_post_rate(ip):
            self._json({"error": "rate_limited"}, 429)
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_PAYLOAD_BYTES:
            self._json({"error": "payload_too_large"}, 413)
            return
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._json({"error": "bad_request"}, 400)
            return
        payload = data.get("payload")
        iv = data.get("iv")
        if not payload or not iv or len(payload) + len(iv) > MAX_PAYLOAD_BYTES:
            self._json({"error": "missing_payload"}, 400)
            return
        sid, err = _store_secret(payload, iv, self.secret_ttl)
        if err == "storage_full":
            self._json({"error": "storage_full"}, 503)
            return
        self._json({"id": sid, "ttl": self.secret_ttl})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--ttl", type=float, default=DEFAULT_TTL_SECONDS,
                    help="seconds a secret lives before auto-delete")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (keep behind a proxy; default 127.0.0.1)")
    args = ap.parse_args()

    handler = type("DropHandlerBound", (DropHandler,), {"secret_ttl": args.ttl})
    httpd = ThreadingHTTPServer((args.host, args.port), handler)

    def _sweeper():
        while True:
            time.sleep(SWEEP_INTERVAL_SECONDS)
            _sweep_expired(args.ttl)
    threading.Thread(target=_sweeper, daemon=True).start()

    print(f"Secret Drop listening on {args.host}:{args.port} (ttl={args.ttl}s)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()