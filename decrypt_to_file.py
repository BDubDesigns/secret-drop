#!/usr/bin/env python3
"""Receiver-side shh helper.

The helper creates a one-time receiver keypair, prints a delivery link containing
only the public key, polls the relay for an opaque sealed-box payload, decrypts
locally, and atomically updates one declared ``.env`` file. The plaintext is
never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from nacl.public import PrivateKey, SealedBox
from nacl.secret import SecretBox
from nacl import utils


_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_ASSIGNMENT_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<export>export[ \t]+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<spacing>[ \t]*=[ \t]*)"
    r"(?P<value>.*?)(?P<newline>\r?\n)?$"
)
_MAX_VALUE_BYTES = 1_000_000


def _validate_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise ValueError("variable name is not a valid environment variable")


def _validate_target(target: Path) -> None:
    if not target.is_absolute():
        raise ValueError("target must be an absolute path")
    if target.name != ".env":
        raise ValueError("target basename must be .env")
    if not target.parent.is_dir():
        raise ValueError("target parent directory must exist")
    if target.is_symlink():
        raise ValueError("target must not be a symlink")
    if target.exists() and not target.is_file():
        raise ValueError("target must be a regular file")


def _quote_env_value(value: str) -> str:
    """Render a python-dotenv-compatible single-quoted value."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _updated_env_text(existing: str, name: str, value: str) -> str:
    newline = "\r\n" if "\r\n" in existing else "\n"
    lines = existing.splitlines(keepends=True)
    matches: list[int] = []
    for index, line in enumerate(lines):
        match = _ENV_ASSIGNMENT_RE.match(line)
        if match and match.group("name") == name:
            matches.append(index)
    if len(matches) > 1:
        raise ValueError("duplicate variable assignment")

    rendered = _quote_env_value(value)
    if matches:
        index = matches[0]
        match = _ENV_ASSIGNMENT_RE.match(lines[index])
        assert match is not None
        ending = match.group("newline") or ""
        lines[index] = (
            match.group("indent")
            + (match.group("export") or "")
            + name
            + "="
            + rendered
            + ending
        )
        return "".join(lines)

    if lines and not lines[-1].endswith(("\n", "\r")):
        lines.append(newline)
    lines.append(f"{name}={rendered}{newline}")
    return "".join(lines)


def write_env_value(target: Path | str, name: str, value: str) -> None:
    """Atomically insert or replace one variable in a declared .env target."""
    target_path = Path(target)
    _validate_name(name)
    _validate_target(target_path)
    if not isinstance(value, str) or "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("secret must be one line of UTF-8 text")
    if "${" in value:
        raise ValueError("secret contains unsupported dotenv interpolation syntax")
    if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise ValueError("secret is too large")

    if target_path.exists():
        try:
            existing = target_path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("target is not valid UTF-8") from exc
        mode = 0o600
    else:
        existing = ""
        mode = 0o600

    updated = _updated_env_text(existing, name, value).encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".shh-", dir=target_path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target_path)
        directory_fd = os.open(target_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("invalid payload encoding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise ValueError("invalid payload encoding") from exc


def _relay_url(relay: str, path: str) -> str:
    parsed = urlsplit(relay)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("relay must be an http(s) origin")
    return relay.rstrip("/") + path


def _json_request(url: str, method: str, body: dict) -> tuple[int, dict | None]:
    request = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except Exception:
            body = None
        return exc.code, body
    except (URLError, TimeoutError, OSError):
        return 0, None


def receive(relay: str, name: str, target: Path | str, poll_interval: float = 2.0) -> int:
    """Run one receiver handoff. Returns a process exit code."""
    try:
        _validate_name(name)
        target_path = Path(target)
        _validate_target(target_path)
        relay = relay.rstrip("/")
        private_key = PrivateKey.generate()
        status, created = _json_request(_relay_url(relay, "/api/drops"), "POST", {})
        if status != 201 or not isinstance(created, dict):
            print("error: relay could not create a drop", file=sys.stderr)
            return 3
        drop_id = created.get("id")
        ttl = created.get("ttl")
        if not isinstance(drop_id, str) or not isinstance(ttl, (int, float)):
            print("error: relay returned an invalid drop", file=sys.stderr)
            return 3

        link = f"{relay}/#{drop_id}.{_b64url(bytes(private_key.public_key))}"
        print(f"shh link: {link}", flush=True)
        print("shh: waiting for handoff...", flush=True)
        deadline = time.monotonic() + max(1.0, float(ttl))
        encrypted: bytes | None = None
        while time.monotonic() < deadline:
            status, claimed = _json_request(
                _relay_url(relay, f"/api/drops/{drop_id}/claim"), "POST", {}
            )
            if status == 202 and isinstance(claimed, dict) and claimed.get("status") == "pending":
                time.sleep(max(0.1, poll_interval))
                continue
            if status == 200 and isinstance(claimed, dict) and claimed.get("v") == 1:
                encoded = claimed.get("payload")
                if isinstance(encoded, str):
                    encrypted = _decode_b64url(encoded)
                break
            if status in {404, 410}:
                print("error: drop expired or unavailable", file=sys.stderr)
                return 4
            print("error: relay returned an invalid claim", file=sys.stderr)
            return 3
        if encrypted is None:
            print("error: drop expired before delivery", file=sys.stderr)
            return 4
        try:
            plaintext = SealedBox(private_key).decrypt(encrypted).decode("utf-8")
        except Exception:
            print("error: could not decrypt the delivered payload", file=sys.stderr)
            return 5
        try:
            write_env_value(target_path, name, plaintext)
        except ValueError as exc:
            # ValueError messages describe validation, never the value itself.
            print(f"error: {exc}", file=sys.stderr)
            return 6
        print(f"ok: delivered {name} to the approved target.", flush=True)
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # Do not surface library/network exceptions: they can contain request data.
        print("error: receiver failed without writing the secret", file=sys.stderr)
        return 3


def release(
    relay: str,
    secret: str,
) -> int:
    """Publish one secret for a human to reveal once via the browser.

    The agent holds the secret (e.g. from a file or a generated value) and
    wants to hand it to the human without putting the plaintext in chat,
    model context, or normal tool output. This helper encrypts the secret
    with a fresh symmetric key, submits only ciphertext to the blind relay,
    and prints a reveal link whose fragment carries the drop id and the key.
    The human opens the reveal page, which claims the drop once, decrypts in
    the browser, and shows the plaintext. Returns a process exit code.
    """
    try:
        relay = relay.rstrip("/")
        status, created = _json_request(_relay_url(relay, "/api/drops"), "POST", {})
        if status != 201 or not isinstance(created, dict):
            print("error: relay could not create a drop", file=sys.stderr)
            return 3
        drop_id = created.get("id")
        if not isinstance(drop_id, str):
            print("error: relay returned an invalid drop", file=sys.stderr)
            return 3

        key = utils.random(SecretBox.KEY_SIZE)
        encrypted = SecretBox(key).encrypt(secret.encode("utf-8"))
        payload = _b64url(bytes(encrypted))
        status, _ = _json_request(
            _relay_url(relay, f"/api/drops/{drop_id}/payload"),
            "POST",
            {"v": 1, "payload": payload},
        )
        if status != 204:
            print("error: relay rejected the secret payload", file=sys.stderr)
            return 3

        link = f"{relay}/reveal#{drop_id}.{_b64url(bytes(key))}"
        print(f"shh reveal link: {link}", flush=True)
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # Do not surface library/network exceptions: they can contain request data.
        print("error: release failed without publishing the secret", file=sys.stderr)
        return 3


def main() -> int:
    parser = argparse.ArgumentParser(prog="shh")
    subparsers = parser.add_subparsers(dest="command", required=True)
    receiver = subparsers.add_parser("receive", help="request one secret handoff")
    receiver.add_argument("--relay", required=True, help="shh relay origin")
    receiver.add_argument("--name", required=True, help="environment variable name")
    receiver.add_argument("--target", required=True, help="absolute path whose basename is .env")
    receiver.add_argument("--poll-interval", type=float, default=2.0)
    releaser = subparsers.add_parser("release", help="publish one secret for a one-time browser reveal")
    releaser.add_argument("--relay", required=True, help="shh relay origin")
    releaser.add_argument(
        "--secret",
        help="secret to publish (omit to read from stdin; piping avoids argv/process-list exposure)",
    )
    args = parser.parse_args()
    if args.command == "receive":
        return receive(args.relay, args.name, args.target, args.poll_interval)
    if args.command == "release":
        secret = args.secret
        if secret is None:
            secret = sys.stdin.read()
        return release(args.relay, secret)
    return 2


if __name__ == "__main__":
    sys.exit(main())
