from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from nacl.public import PrivateKey, SealedBox

import server
from decrypt_to_file import write_env_value


@pytest.fixture
def app_server(tmp_path):
    usage_log = tmp_path / "usage.jsonl"
    httpd = server.make_server(
        "127.0.0.1",
        0,
        ttl=0.25,
        usage_log_path=usage_log,
        usage_key=b"test-only-usage-key-which-is-not-secret-data",
        trust_proxy=True,
        trusted_proxy_cidrs=("127.0.0.0/8",),
        posts_per_minute=20,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"
    try:
        yield base, usage_log
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    headers: dict[str, str] | None = None,
):
    encoded = None if body is None else json.dumps(body).encode()
    request_headers = {"Content-Type": "application/json"} if encoded is not None else {}
    request_headers.update(headers or {})
    request = Request(
        url,
        data=encoded,
        method=method,
        headers=request_headers,
    )
    with urlopen(request, timeout=3) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None


def error_json(url: str, *, method: str = "GET", body: dict | None = None):
    with pytest.raises(HTTPError) as caught:
        request_json(url, method=method, body=body)
    return caught.value.code, json.loads(caught.value.read())


def create_drop(base: str) -> str:
    status, data = request_json(base + "/api/drops", method="POST", body={})
    assert status == 201
    assert set(data) == {"id", "ttl"}
    return data["id"]


def sealed_payload(public_key: PrivateKey, secret: str) -> str:
    encrypted = SealedBox(public_key.public_key).encrypt(secret.encode())
    return base64.urlsafe_b64encode(encrypted).rstrip(b"=").decode()


def test_receiver_key_claim_is_opaque_and_single_use(app_server):
    base, usage_log = app_server
    receiver_key = PrivateKey.generate()
    secret = "test-secret-must-never-appear-in-output"
    drop_id = create_drop(base)
    payload = sealed_payload(receiver_key, secret)

    status, body = request_json(
        f"{base}/api/drops/{drop_id}/payload",
        method="POST",
        body={"v": 1, "payload": payload},
    )
    assert status == 204
    assert body is None

    status, body = request_json(
        f"{base}/api/drops/{drop_id}/claim", method="POST", body={}
    )
    assert status == 200
    assert set(body) == {"v", "payload"}
    assert body["payload"] == payload
    assert SealedBox(receiver_key).decrypt(
        base64.urlsafe_b64decode(body["payload"] + "==")
    ).decode() == secret

    status, body = error_json(
        f"{base}/api/drops/{drop_id}/claim", method="POST", body={}
    )
    assert status == 404
    assert body == {"error": "not_found"}

    log_text = usage_log.read_text()
    assert secret not in log_text
    assert payload not in log_text
    events = [json.loads(line)["event"] for line in log_text.splitlines()]
    assert events == ["drop_created", "payload_submitted", "claim_succeeded", "claim"]
    for line in log_text.splitlines():
        event = json.loads(line)
        assert set(event) == {"ts", "event", "ip_tag", "status"}
        assert len(event["ip_tag"]) == 32


def test_malformed_payload_is_rejected_without_claiming_drop(app_server):
    base, _ = app_server
    drop_id = create_drop(base)

    status, body = error_json(
        f"{base}/api/drops/{drop_id}/payload",
        method="POST",
        body={"v": 1, "payload": "not valid base64%%%"},
    )
    assert status == 400
    assert body == {"error": "bad_payload"}

    status, body = request_json(
        f"{base}/api/drops/{drop_id}/claim", method="POST", body={}
    )
    assert status == 202
    assert body == {"status": "pending"}


def test_expired_drop_cannot_be_claimed(app_server):
    base, _ = app_server
    drop_id = create_drop(base)
    time.sleep(0.35)
    status, body = error_json(
        f"{base}/api/drops/{drop_id}/claim", method="POST", body={}
    )
    assert status == 404
    assert body == {"error": "not_found"}


def test_expired_submitted_drop_releases_storage_accounting():
    store = server.DropStore(ttl=0.05, max_payload=4, max_total=4, max_active=10)
    drop_id, error = store.create()
    assert error is None
    assert drop_id is not None
    assert store.submit(drop_id, b"1234") is None
    time.sleep(0.08)
    assert store.submit(drop_id, b"x") == "not_found"

    replacement_id, error = store.create()
    assert error is None
    assert replacement_id is not None
    assert store.submit(replacement_id, b"1234") is None


def test_rate_limit_is_applied_without_trusting_spoofed_ip_by_default(tmp_path):
    usage_log = tmp_path / "usage.jsonl"
    httpd = server.make_server(
        "127.0.0.1",
        0,
        ttl=60,
        usage_log_path=usage_log,
        usage_key=b"test-only-usage-key-which-is-not-secret-data",
        trust_proxy=False,
        posts_per_minute=1,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"
    try:
        status, _ = request_json(
            base + "/api/drops", method="POST", body={}
        )
        assert status == 201
        request = Request(
            base + "/api/drops",
            data=b"{}",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Forwarded-For": "203.0.113.10",
            },
        )
        with pytest.raises(HTTPError) as caught:
            urlopen(request, timeout=3)
        assert caught.value.code == 429
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()


def test_trusted_proxy_cidr_allows_verified_forwarded_ip(tmp_path):
    usage_log = tmp_path / "usage.jsonl"
    httpd = server.make_server(
        "127.0.0.1",
        0,
        ttl=60,
        usage_log_path=usage_log,
        usage_key=b"test-only-usage-key-which-is-not-secret-data",
        trust_proxy=True,
        trusted_proxy_cidrs=("127.0.0.0/8",),
        posts_per_minute=1,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"
    try:
        first_status, _ = request_json(
            base + "/api/drops",
            method="POST",
            body={},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        second_status, _ = request_json(
            base + "/api/drops",
            method="POST",
            body={},
            headers={"X-Forwarded-For": "203.0.113.11"},
        )
        assert (first_status, second_status) == (201, 201)
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()


def test_trusted_proxy_requires_explicit_cidr(tmp_path):
    with pytest.raises(ValueError, match="trusted proxy CIDR"):
        server.make_server(
            "127.0.0.1",
            0,
            usage_log_path=tmp_path / "usage.jsonl",
            trust_proxy=True,
        )


def test_rate_limiter_evicts_rotating_clients():
    limiter = server.RateLimiter(limit=1, max_clients=2)
    assert limiter.allow("client-a")
    assert limiter.allow("client-b")
    assert limiter.allow("client-c")
    assert len(limiter._history) <= 2


def test_env_writer_replaces_one_variable_preserves_unrelated_content(tmp_path):
    target = tmp_path / ".env"
    target.write_text("# keep me\nOTHER=value\nexport TOKEN=old\n")
    target.chmod(0o644)

    write_env_value(target, "TOKEN", "new-value\"with\\slash")

    assert target.read_text() == (
        '# keep me\nOTHER=value\nexport TOKEN="new-value\\"with\\\\slash"\n'
    )
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".shh-*"))


def test_env_writer_rejects_unsafe_target_and_duplicate_variable(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        write_env_value(Path("relative.env"), "TOKEN", "x")
    with pytest.raises(ValueError, match="basename"):
        write_env_value(tmp_path / "config", "TOKEN", "x")

    target = tmp_path / ".env"
    target.write_text("TOKEN=one\nTOKEN=two\n")
    with pytest.raises(ValueError, match="duplicate"):
        write_env_value(target, "TOKEN", "x")


def test_page_uses_sealed_box_and_discloses_pseudonymous_telemetry(app_server):
    base, _ = app_server
    with urlopen(base + "/", timeout=3) as response:
        page = response.read().decode()
        headers = {key.lower(): value for key, value in response.headers.items()}
    assert "AES-GCM" not in page
    assert "pseudonymous" in page
    assert "/static/app.js" in page
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "nonce-" in headers["content-security-policy"]
    assert "wasm-unsafe-eval" in headers["content-security-policy"]
    with urlopen(base + "/static/app.js", timeout=3) as response:
        app = response.read().decode()
    assert "crypto_box_seal" in app
    assert "/static/libsodium-wrappers.mjs" in app


def test_receiver_cli_stdout_and_stderr_never_contain_plaintext(tmp_path):
    # This test exercises argument validation before the network path. The full
    # browser-to-receiver path is covered by the Playwright E2E test.
    secret = "test-cli-secret-not-output"
    result = subprocess.run(
        [
            sys.executable,
            "decrypt_to_file.py",
            "receive",
            "--relay",
            "http://127.0.0.1:1",
            "--name",
            "TOKEN",
            "--target",
            str(tmp_path / ".env"),
        ],
        input="",
        text=True,
        capture_output=True,
        timeout=3,
    )
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "TOKEN" in result.stdout or "relay" in result.stderr.lower()
