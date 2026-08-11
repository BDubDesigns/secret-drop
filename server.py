#!/usr/bin/env python3
"""shh: a small, anonymous, single-use encrypted handoff relay.

The receiver helper creates the drop and keeps the private key. The browser
uses libsodium's sealed-box primitive to encrypt directly to the receiver's
public key. This server stores only opaque ciphertext in RAM.

This milestone deliberately uses one origin for the page and relay. It
protects against plaintext entering chat/model context, normal tool output, or
relay storage. It does not protect against a compromised relay serving altered
JavaScript; the architecture document calls that boundary out explicitly.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_TTL_SECONDS = 1800.0
MAX_PAYLOAD_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_ACTIVE_DROPS = 1_000
MAX_POSTS_PER_MINUTE = 10
MAX_CLAIMS_PER_MINUTE = 120
SWEEP_INTERVAL_SECONDS = 30.0
USAGE_LOG_RETENTION_SECONDS = 14 * 24 * 60 * 60
USAGE_LOG_MAX_BYTES = 5_000_000
DROP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
STATIC_ROOT = Path(__file__).with_name("static")
VENDOR_ROOT = Path(__file__).with_name("vendor")
AGENT_GUIDE_PATH = Path(__file__).with_name("docs") / "agent.md"
LLMS_PATH = Path(__file__).with_name("llms.txt")
STATIC_FILES = {
    "app.js": (STATIC_ROOT / "app.js", "application/javascript; charset=utf-8"),
    "app_reveal.js": (STATIC_ROOT / "app_reveal.js", "application/javascript; charset=utf-8"),
    "app.css": (STATIC_ROOT / "app.css", "text/css; charset=utf-8"),
    "libsodium.mjs": (VENDOR_ROOT / "libsodium.mjs", "application/javascript; charset=utf-8"),
    "libsodium-wrappers.mjs": (
        VENDOR_ROOT / "libsodium-wrappers.mjs",
        "application/javascript; charset=utf-8",
    ),
}


@dataclass
class Drop:
    created: float
    ttl: float
    payload: bytes | None = None
    status: str = "pending"


class DropStore:
    """Bounded RAM-only store with atomic submit and claim operations."""

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_payload: int = MAX_PAYLOAD_BYTES,
        max_total: int = MAX_TOTAL_BYTES,
        max_active: int = MAX_ACTIVE_DROPS,
    ) -> None:
        self.ttl = ttl
        self.max_payload = max_payload
        self.max_total = max_total
        self.max_active = max_active
        self._drops: dict[str, Drop] = {}
        self._total_bytes = 0
        self._lock = threading.Lock()

    def _expired(self, item: Drop, now: float) -> bool:
        return now - item.created > item.ttl

    def _remove_expired_locked(self, now: float) -> None:
        for drop_id, item in list(self._drops.items()):
            if self._expired(item, now):
                if item.payload is not None:
                    self._total_bytes -= len(item.payload)
                del self._drops[drop_id]
        self._total_bytes = max(0, self._total_bytes)

    def create(self) -> tuple[str | None, str | None]:
        with self._lock:
            self._remove_expired_locked(time.time())
            if len(self._drops) >= self.max_active:
                return None, "storage_full"
            drop_id = secrets.token_urlsafe(24)
            self._drops[drop_id] = Drop(created=time.time(), ttl=self.ttl)
            return drop_id, None

    def submit(self, drop_id: str, payload: bytes) -> str | None:
        if len(payload) > self.max_payload:
            return "payload_too_large"
        with self._lock:
            now = time.time()
            self._remove_expired_locked(now)
            item = self._drops.get(drop_id)
            if item is None:
                return "not_found"
            if item.status != "pending":
                return "already_submitted"
            if self._total_bytes + len(payload) > self.max_total:
                return "storage_full"
            item.payload = payload
            item.status = "submitted"
            self._total_bytes += len(payload)
            return None

    def claim(self, drop_id: str) -> tuple[str, bytes | None]:
        with self._lock:
            item = self._drops.get(drop_id)
            if item is None or self._expired(item, time.time()):
                if item is not None:
                    if item.payload is not None:
                        self._total_bytes -= len(item.payload)
                    del self._drops[drop_id]
                self._total_bytes = max(0, self._total_bytes)
                return "not_found", None
            if item.status == "pending":
                return "pending", None
            if item.status == "claimed" or item.payload is None:
                return "not_found", None
            payload = item.payload
            self._total_bytes -= len(payload)
            item.payload = None
            item.status = "claimed"
            self._total_bytes = max(0, self._total_bytes)
            return "claimed", payload

    def status(self, drop_id: str) -> str | None:
        with self._lock:
            item = self._drops.get(drop_id)
            if item is None or self._expired(item, time.time()):
                return None
            return item.status

    def sweep(self) -> None:
        with self._lock:
            self._remove_expired_locked(time.time())


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        max_clients: int = 10_000,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._history: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if client_id not in self._history and len(self._history) >= self.max_clients:
                stale = next(
                    (key for key, stamps in self._history.items() if not stamps or stamps[-1] <= cutoff),
                    None,
                )
                del self._history[stale or next(iter(self._history))]
            recent = [stamp for stamp in self._history.get(client_id, []) if stamp > cutoff]
            if len(recent) >= self.limit:
                self._history[client_id] = recent
                return False
            recent.append(now)
            self._history[client_id] = recent
            return True


class UsageLogger:
    """Short-lived, local, pseudonymous abuse/usage telemetry."""

    def __init__(
        self,
        path: Path | str,
        *,
        key: bytes | None = None,
        retention_seconds: float = USAGE_LOG_RETENTION_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.key = key or secrets.token_bytes(32)
        self.retention_seconds = retention_seconds
        self._lock = threading.Lock()

    def _ip_tag(self, ip: str) -> str:
        return hmac.new(self.key, ip.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]

    def _prune_locked(self, now: dt.datetime) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size > USAGE_LOG_MAX_BYTES:
            keep: list[str] = []
        else:
            keep = []
            cutoff = now.timestamp() - self.retention_seconds
            try:
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    try:
                        record = json.loads(line)
                        stamp = dt.datetime.fromisoformat(record["ts"].replace("Z", "+00:00")).timestamp()
                        if stamp >= cutoff and set(record) == {"ts", "event", "ip_tag", "status"}:
                            keep.append(json.dumps(record, separators=(",", ":")))
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                        continue
            except OSError:
                keep = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(f".{self.path.name}.prune-{secrets.token_hex(8)}")
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("" if not keep else "\n".join(keep) + "\n")
            os.replace(temp, self.path)
            os.chmod(self.path, 0o600)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def maintain(self, now: dt.datetime | None = None) -> None:
        """Bound log retention outside the request event path."""
        now = now or dt.datetime.now(dt.timezone.utc)
        with self._lock:
            self._prune_locked(now)

    def record(self, event: str, ip: str, status: str) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        record = {
            "ts": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "event": event,
            "ip_tag": self._ip_tag(ip),
            "status": status,
        }
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            finally:
                if fd >= 0:
                    os.close(fd)


def _decode_payload(text: Any) -> bytes:
    if not isinstance(text, str) or not B64URL_RE.fullmatch(text):
        raise ValueError("bad_payload")
    if len(text) > ((MAX_PAYLOAD_BYTES + 2) * 4 // 3) + 4:
        raise ValueError("payload_too_large")
    try:
        payload = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise ValueError("bad_payload") from exc
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload_too_large")
    if base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii") != text:
        raise ValueError("bad_payload")
    return payload


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _page_csp(nonce: str) -> str:
    return (
        "default-src 'none'; script-src 'self' 'nonce-"
        + nonce
        + "' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'"
    )


def _build_page(ttl_seconds: float) -> tuple[str, str]:
    ttl_min = max(1, int(ttl_seconds // 60))
    nonce = secrets.token_urlsafe(18)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>shh — one-time secret bridge</title>
<meta name="description" content="A one-time secret bridge for humans and AI agents.">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<div class="page-shell landing-shell">
<header class="site-header">
  <a class="brand" href="/" aria-label="shh home"><span class="brand-mark">shh</span></a>
  <span class="eyebrow">one-time secret bridge</span>
</header>
<main>
  <section id="landing" aria-labelledby="hero-title">
    <div class="hero">
      <p class="eyebrow">Private handoffs, without chat</p>
      <h1 id="hero-title">A one-time secret bridge for humans and AI agents.</h1>
      <p class="lede">shh keeps plaintext out of chat and model context while a declared receiver or human claims it once. The hosted instance is a best-effort public demo; shh is open source and self-hostable.</p>
      <div class="badge-row" aria-label="Product properties">
        <span class="badge badge-positive">open source</span>
        <span class="badge">MIT</span>
        <span class="badge">self-hostable</span>
        <span class="badge badge-positive">blind relay</span>
      </div>
    </div>

    <p id="handoff-message" class="alert" role="status">No handoff link detected. Ask your agent to create one.</p>

    <div class="flow-grid">
      <section class="flow-card" aria-labelledby="human-agent-title">
        <p class="eyebrow">Declared receiver</p>
        <h2 id="human-agent-title">Human → Agent</h2>
        <p>The agent creates a one-time link with its public key. You encrypt the value in this browser, and the receiver claims it and writes the approved target locally.</p>
        <ol class="step-list">
          <li><span class="step-number">1</span><span>Agent creates the handoff and names the destination.</span></li>
          <li><span class="step-number">2</span><span>Human opens the complete link and encrypts in the browser.</span></li>
          <li><span class="step-number">3</span><span>Agent decrypts locally and writes one approved value.</span></li>
        </ol>
      </section>
      <section class="flow-card" aria-labelledby="agent-human-title">
        <p class="eyebrow">One-time reveal</p>
        <h2 id="agent-human-title">Agent → Human</h2>
        <p>The agent publishes ciphertext from stdin and sends a reveal link. You claim it once in the browser, with explicit controls for copying or hiding the value.</p>
        <ol class="step-list">
          <li><span class="step-number">1</span><span>Agent publishes a value without putting it in chat.</span></li>
          <li><span class="step-number">2</span><span>Human opens the reveal link and claims it once.</span></li>
          <li><span class="step-number">3</span><span>The browser clears the capability and display when finished.</span></li>
        </ol>
      </section>
    </div>

    <aside class="agent-callout" aria-labelledby="agent-guide-title">
      <div>
        <p class="eyebrow">Machine-readable onboarding</p>
        <h2 id="agent-guide-title">Using an AI agent?</h2>
        <p>Give it the supported guide. It explains the exact helper commands and the trust model without asking anyone to paste a secret into chat.</p>
      </div>
      <code id="agent-url" class="url">https://shh.qcfailed.com/agent.md</code>
      <div class="button-row">
        <a href="/agent.md">Read the agent guide</a>
        <button id="copy-agent-url" class="button-secondary" type="button">Copy agent URL</button>
      </div>
      <p id="agent-copy-status" class="note" role="status" hidden></p>
    </aside>

    <p class="trust-note"><strong>Trust summary:</strong> the expected browser implementation encrypts before upload and the relay stores opaque ciphertext. The same-origin operator serves this JavaScript and could replace it to capture a future plaintext. Short TTLs and one-time claims are lifecycle controls, not identity or access control.</p>
  </section>

  <section id="delivery" class="task-shell panel" aria-labelledby="delivery-title" hidden>
    <p class="eyebrow">Active handoff</p>
    <h2 id="delivery-title">Deliver your secret</h2>
    <p>Paste one secret for the receiver who created this link. Your browser encrypts it with the receiver's one-time public key before upload. The relay stores only ciphertext and the drop expires after {ttl_min} minutes.</p>
    <label for="input">Secret</label>
    <textarea id="input" autocomplete="off" spellcheck="false" placeholder="Paste the secret here..."></textarea>
    <div class="button-row">
      <button id="send" type="button" disabled>Encrypt &amp; deliver</button>
    </div>
    <div id="status" role="status" aria-live="polite"></div>
    <p class="note">For abuse monitoring, this service records a short-lived pseudonymous client identifier, timestamp, event, and status. It does not record secret contents, links, target paths, or request bodies. Logs are retained locally for 14 days.</p>
    <div class="alert"><b>Trust boundary:</b> this service keeps the secret out of chat, model context, normal tool output, and relay storage. It assumes this origin serves the expected browser code; a compromised relay could alter new submissions.</div>
  </section>
</main>
<footer class="site-footer">
  <a href="https://github.com/BDubDesigns/secret-drop">GitHub</a>
  <a href="https://github.com/BDubDesigns/secret-drop/blob/main/docs/architecture-security.md">Architecture &amp; security</a>
  <a href="https://github.com/BDubDesigns/secret-drop#deployment">Self-hosting</a>
  <a href="https://qcfailed.com">Built by Brandon Werner</a>
</footer>
</div>
<script type="importmap" nonce="{nonce}">{{"imports":{{"libsodium":"/static/libsodium.mjs"}}}}</script>
<script type="module" nonce="{nonce}" src="/static/app.js"></script>
</body>
</html>""", nonce


def _build_reveal_page(ttl: float) -> tuple[str, str]:
    nonce = secrets.token_urlsafe(18)
    ttl_min = max(1, int(round(ttl / 60)))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>shh — reveal secret</title>
<meta name="description" content="Reveal a one-time secret delivered by the agent.">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<div class="page-shell task-shell">
<header class="site-header">
  <a class="brand" href="/" aria-label="shh home"><span class="brand-mark">shh</span></a>
  <span class="eyebrow">one-time reveal</span>
</header>
<main class="panel">
  <p class="eyebrow">Agent → Human</p>
  <h1>Reveal secret</h1>
  <p>A secret was delivered through the relay for you. This link works once and expires after {ttl_min} minute(s).</p>
  <button id="reveal" type="button">Reveal secret</button>
  <div id="status" role="status" aria-live="polite"></div>
  <h2 id="secret-heading" hidden>Revealed secret</h2>
  <textarea id="secret" aria-label="Revealed secret" aria-describedby="secret-note" autocomplete="off" spellcheck="false" readonly hidden></textarea>
  <div id="secret-actions" class="button-row" hidden>
    <button id="copy-secret" type="button">Copy secret</button>
    <button id="hide-secret" class="button-secondary" type="button">Hide now</button>
  </div>
  <p id="secret-note" class="note">The relay stores only ciphertext and deletes it after a single claim. The revealed value is hidden when you leave the page and after a bounded 120-second screen/privacy fallback. Copying moves plaintext into the system clipboard, which is outside shh's control.</p>
  <div class="alert"><b>Trust boundary:</b> keep this link private until you reveal it. Anyone who opens it before you can claim the secret, and once claimed it is gone.</div>
</main>
<footer class="site-footer">
  <a href="https://github.com/BDubDesigns/secret-drop">GitHub</a>
  <a href="https://github.com/BDubDesigns/secret-drop/blob/main/docs/architecture-security.md">Architecture &amp; security</a>
  <a href="https://qcfailed.com">Built by Brandon Werner</a>
</footer>
</div>
<script type="importmap" nonce="{nonce}">{{"imports":{{"libsodium":"/static/libsodium.mjs"}}}}</script>
<script type="module" nonce="{nonce}" src="/static/app_reveal.js"></script>
</body>
</html>""", nonce


class DropHandler(BaseHTTPRequestHandler):
    store: DropStore
    create_limiter: RateLimiter
    submit_limiter: RateLimiter
    claim_limiter: RateLimiter
    usage: UsageLogger
    secret_ttl: float
    trust_proxy: bool
    trusted_proxy_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Deliberately suppress default request logging: URLs can contain drop IDs.
        return

    def _client_ip(self) -> str:
        peer_ip = self.client_address[0]
        if self.trust_proxy:
            try:
                peer = ipaddress.ip_address(peer_ip)
            except ValueError:
                peer = None
            trusted_peer = peer is not None and any(
                peer in network for network in self.trusted_proxy_networks
            )
            forwarded = self.headers.get("X-Forwarded-For", "")
            if trusted_peer and forwarded:
                candidate = forwarded.split(",", 1)[0].strip()
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass
        return peer_ip

    def _send(
        self,
        code: int,
        body: bytes,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value: dict[str, Any], code: int = 200) -> None:
        self._send(code, _json_bytes(value))

    def _read_json(self, limit: int) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    def _has_json_content_type(self) -> bool:
        return self.headers.get_content_type().lower() == "application/json"

    def _drop_id(self, path: str, suffix: str) -> str | None:
        prefix = "/api/drops/"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        drop_id = path[len(prefix) : -len(suffix)]
        return drop_id if DROP_ID_RE.fullmatch(drop_id) else None

    def _rate_limited(self, limiter: RateLimiter, ip: str, event: str) -> bool:
        if limiter.allow(ip):
            return False
        self.usage.record(event, ip, "rate_limited")
        self._json({"error": "rate_limited"}, 429)
        return True

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        ip = self._client_ip()
        if path in {"/", "/index.html"}:
            page, nonce = _build_page(self.secret_ttl)
            body = page.encode("utf-8")
            self._send(
                200,
                body,
                "text/html; charset=utf-8",
                {"Content-Security-Policy": _page_csp(nonce)},
            )
            return
        if path == "/reveal":
            page, nonce = _build_reveal_page(self.secret_ttl)
            body = page.encode("utf-8")
            self._send(
                200,
                body,
                "text/html; charset=utf-8",
                {"Content-Security-Policy": _page_csp(nonce)},
            )
            return
        if path == "/robots.txt":
            self._send(200, b"User-agent: *\nAllow: /\n", "text/plain; charset=utf-8")
            return
        if path == "/agent.md":
            if not AGENT_GUIDE_PATH.is_file():
                self._json({"error": "not_found"}, 404)
                return
            self._send(
                200,
                AGENT_GUIDE_PATH.read_bytes(),
                "text/markdown; charset=utf-8",
            )
            return
        if path == "/llms.txt":
            if not LLMS_PATH.is_file():
                self._json({"error": "not_found"}, 404)
                return
            self._send(200, LLMS_PATH.read_bytes(), "text/plain; charset=utf-8")
            return
        if path == "/healthz":
            self._json({"status": "ok"})
            return
        if path.startswith("/static/"):
            filename = path.removeprefix("/static/")
            file_entry = STATIC_FILES.get(filename)
            if file_entry is None:
                self._json({"error": "not_found"}, 404)
                return
            file_path, content_type = file_entry
            if not file_path.is_file():
                self._json({"error": "not_found"}, 404)
                return
            self._send(200, file_path.read_bytes(), content_type)
            return
        if path.startswith("/out/") or path == "/secret":
            self._json({"error": "legacy_endpoint_removed"}, 410)
            return
        if path.startswith("/api/drops/"):
            drop_id = path.removeprefix("/api/drops/")
            if not DROP_ID_RE.fullmatch(drop_id):
                self._json({"error": "not_found"}, 404)
                return
            status = self.store.status(drop_id)
            if status is None:
                self._json({"error": "not_found"}, 404)
            else:
                self._json({"status": status})
            return
        self._json({"error": "not_found"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        ip = self._client_ip()
        if path == "/api/drops":
            if not self._has_json_content_type():
                self._json({"error": "unsupported_media_type"}, 415)
                return
            if self._rate_limited(self.create_limiter, ip, "drop_created"):
                return
            if self._read_json(4096) is None:
                self.usage.record("drop_created", ip, "bad_request")
                self._json({"error": "bad_request"}, 400)
                return
            drop_id, error = self.store.create()
            if error:
                self.usage.record("drop_created", ip, error)
                self._json({"error": error}, 503)
                return
            self.usage.record("drop_created", ip, "ok")
            self._json({"id": drop_id, "ttl": self.secret_ttl}, 201)
            return

        payload_drop = self._drop_id(path, "/payload")
        if payload_drop is not None:
            if not self._has_json_content_type():
                self._json({"error": "unsupported_media_type"}, 415)
                return
            if self._rate_limited(self.submit_limiter, ip, "payload_submitted"):
                return
            data = self._read_json(MAX_PAYLOAD_BYTES * 2)
            if data is None or data.get("v") != 1:
                self.usage.record("payload_submitted", ip, "bad_payload")
                self._json({"error": "bad_payload"}, 400)
                return
            try:
                payload = _decode_payload(data.get("payload"))
            except ValueError as exc:
                error = str(exc)
                self.usage.record("payload_submitted", ip, error)
                self._json({"error": error}, 413 if error == "payload_too_large" else 400)
                return
            error = self.store.submit(payload_drop, payload)
            if error:
                self.usage.record("payload_submitted", ip, error)
                self._json({"error": error}, 404 if error == "not_found" else 409 if error == "already_submitted" else 503)
                return
            self.usage.record("payload_submitted", ip, "ok")
            self._send(204, b"")
            return

        claim_drop = self._drop_id(path, "/claim")
        if claim_drop is not None:
            if not self._has_json_content_type():
                self._json({"error": "unsupported_media_type"}, 415)
                return
            if self._rate_limited(self.claim_limiter, ip, "claim"):
                return
            if self._read_json(4096) is None:
                self.usage.record("claim", ip, "bad_request")
                self._json({"error": "bad_request"}, 400)
                return
            status, payload = self.store.claim(claim_drop)
            if status == "pending":
                self._json({"status": "pending"}, 202)
                return
            if status == "not_found" or payload is None:
                self.usage.record("claim", ip, "not_found")
                self._json({"error": "not_found"}, 404)
                return
            self.usage.record("claim_succeeded", ip, "ok")
            encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
            self._json({"v": 1, "payload": encoded})
            return

        if path == "/secret":
            self._json({"error": "legacy_endpoint_removed"}, 410)
            return
        self._json({"error": "not_found"}, 404)


def make_server(
    host: str = "127.0.0.1",
    port: int = 8899,
    *,
    ttl: float = DEFAULT_TTL_SECONDS,
    usage_log_path: Path | str = "usage.jsonl",
    usage_key: bytes | None = None,
    trust_proxy: bool = False,
    trusted_proxy_cidrs: tuple[str, ...] = (),
    posts_per_minute: int = MAX_POSTS_PER_MINUTE,
    claims_per_minute: int = MAX_CLAIMS_PER_MINUTE,
) -> ThreadingHTTPServer:
    store = DropStore(ttl=ttl)
    usage = UsageLogger(usage_log_path, key=usage_key)
    usage.maintain()
    if trust_proxy and not trusted_proxy_cidrs:
        raise ValueError("trust_proxy requires at least one trusted proxy CIDR")
    trusted_networks = tuple(ipaddress.ip_network(cidr) for cidr in trusted_proxy_cidrs)
    handler = type(
        "BoundDropHandler",
        (DropHandler,),
        {
            "store": store,
            "create_limiter": RateLimiter(posts_per_minute),
            "submit_limiter": RateLimiter(posts_per_minute),
            "claim_limiter": RateLimiter(claims_per_minute),
            "usage": usage,
            "secret_ttl": ttl,
            "trust_proxy": trust_proxy,
            "trusted_proxy_networks": trusted_networks,
        },
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.shh_store = store  # type: ignore[attr-defined]
    httpd.shh_usage = usage  # type: ignore[attr-defined]
    return httpd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--ttl", type=float, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--usage-log", default="usage.jsonl")
    parser.add_argument(
        "--trust-proxy",
        action="store_true",
        help="use the first X-Forwarded-For value; only enable behind a trusted proxy",
    )
    parser.add_argument(
        "--trusted-proxy-cidr",
        action="append",
        default=None,
        help="CIDR for an immediate trusted proxy peer (may be repeated)",
    )
    args = parser.parse_args()
    if args.ttl <= 0:
        parser.error("--ttl must be positive")
    trusted_proxy_cidrs = tuple(args.trusted_proxy_cidr or ())
    if args.trust_proxy and not trusted_proxy_cidrs:
        parser.error("--trust-proxy requires at least one --trusted-proxy-cidr")
    httpd = make_server(
        args.host,
        args.port,
        ttl=args.ttl,
        usage_log_path=args.usage_log,
        trust_proxy=args.trust_proxy,
        trusted_proxy_cidrs=trusted_proxy_cidrs,
    )

    def sweep() -> None:
        while True:
            time.sleep(SWEEP_INTERVAL_SECONDS)
            httpd.shh_store.sweep()  # type: ignore[attr-defined]
            httpd.shh_usage.maintain()  # type: ignore[attr-defined]

    threading.Thread(target=sweep, daemon=True).start()
    print(f"shh listening on {args.host}:{args.port} (ttl={args.ttl:g}s)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
