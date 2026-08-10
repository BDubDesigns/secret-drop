from __future__ import annotations

import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from dotenv import dotenv_values
from playwright.sync_api import sync_playwright

import server


def assert_plaintext_absent(plaintext: str, *channels: tuple[str, str]) -> None:
    for channel, captured in channels:
        if plaintext in captured:
            raise AssertionError(f"{channel} contained the test plaintext") from None


def output_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def drain_receiver_output(
    receiver: subprocess.Popen[str], plaintext: str, initial_stdout: str, *, timeout: float, phase: str
) -> tuple[str, str]:
    try:
        stdout, stderr = receiver.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        assert_plaintext_absent(
            plaintext,
            ("receiver initial stdout", initial_stdout),
            ("receiver stdout", output_text(exc.stdout)),
            ("receiver stderr", output_text(exc.stderr)),
        )
        raise AssertionError(f"{phase} timed out; protected diagnostics withheld") from None
    assert_plaintext_absent(
        plaintext,
        ("receiver initial stdout", initial_stdout),
        ("receiver stdout", output_text(stdout)),
        ("receiver stderr", output_text(stderr)),
    )
    return output_text(stdout), output_text(stderr)


def test_plaintext_diagnostic_is_redacted():
    plaintext = "synthetic-plaintext-that-must-not-appear-in-failure-output"

    with pytest.raises(AssertionError) as error:
        assert_plaintext_absent(plaintext, ("captured channel", f"prefix-{plaintext}"))

    assert str(error.value) == "captured channel contained the test plaintext"
    assert plaintext not in str(error.value)


def test_plaintext_diagnostic_suppresses_exception_context():
    plaintext = "synthetic-plaintext-that-must-not-appear-in-exception-context"

    try:
        raise RuntimeError(plaintext)
    except RuntimeError:
        with pytest.raises(AssertionError) as error:
            assert_plaintext_absent(plaintext, ("captured channel", f"prefix-{plaintext}"))

    assert error.value.__suppress_context__ is True
    assert plaintext not in str(error.value)


@contextmanager
def browser_test_relay(tmp_path):
    external_relay = os.environ.get("SHH_RELAY_URL")
    if external_relay:
        usage_log_value = os.environ.get("SHH_USAGE_LOG")
        if not usage_log_value:
            raise RuntimeError("SHH_USAGE_LOG is required with SHH_RELAY_URL")
        yield external_relay.rstrip("/"), Path(usage_log_value)
        return

    usage_log = tmp_path / "usage.jsonl"
    httpd = server.make_server(
        "127.0.0.1",
        0,
        ttl=60,
        usage_log_path=usage_log,
        usage_key=b"browser-test-usage-key-which-is-not-secret-data",
        posts_per_minute=20,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", usage_log
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()


def test_browser_encrypts_and_receiver_writes_without_plaintext_leak(tmp_path):
    with browser_test_relay(tmp_path) as (base, usage_log):
        target = tmp_path / ".env"
        secret = os.environ.get(
            "SHH_TEST_PLAINTEXT", "browser-test-secret-must-not-appear-in-captured-output"
        )
        receiver = subprocess.Popen(
            [
                sys.executable,
                "decrypt_to_file.py",
                "receive",
                "--relay",
                base,
                "--name",
                "BROWSER_TEST_TOKEN",
                "--target",
                str(target),
                "--poll-interval",
                "0.1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        link_line = ""
        receiver_drained = False
        try:
            assert receiver.stdout is not None
            link_line = receiver.stdout.readline().strip()
            assert_plaintext_absent(secret, ("receiver initial stdout", link_line))
            if not link_line.startswith("shh link: "):
                if receiver.poll() is None:
                    receiver.kill()
                drain_receiver_output(
                    receiver,
                    secret,
                    link_line,
                    timeout=3,
                    phase="receiver delivery-link check",
                )
                receiver_drained = True
                raise AssertionError("receiver did not emit a delivery link")
            link = link_line.removeprefix("shh link: ")

            console_errors: list[str] = []
            page = None
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
                    )
                    try:
                        page = browser.new_page()
                        page.on(
                            "console",
                            lambda message: console_errors.append(message.text)
                            if message.type == "error"
                            else None,
                        )
                        page.on("pageerror", lambda error: console_errors.append(str(error)))
                        page.goto(link, wait_until="networkidle")
                        page.locator("#input").fill(secret)
                        page.locator("#send").click()
                        page.locator("#status").filter(
                            has_text="Delivered. You can close this tab."
                        ).wait_for(state="attached", timeout=10000)
                        if page.locator("#status").text_content() != "Delivered. You can close this tab.":
                            raise AssertionError("browser did not report delivery success")
                    finally:
                        browser.close()
            except Exception as exc:
                status_text = ""
                if page is not None:
                    try:
                        status_text = page.locator("#status").text_content() or ""
                    except Exception:
                        status_text = "<status unavailable>"
                assert_plaintext_absent(
                    secret,
                    ("browser exception", str(exc)),
                    ("browser status", status_text),
                    ("browser console", "\n".join(console_errors)),
                )
                raise AssertionError(
                    "browser delivery did not complete; protected diagnostics withheld"
                ) from None

            stdout, stderr = drain_receiver_output(
                receiver,
                secret,
                link_line,
                timeout=10,
                phase="receiver",
            )
            receiver_drained = True
            if receiver.returncode != 0:
                raise AssertionError("receiver exited nonzero; protected diagnostics withheld")
            loaded = dotenv_values(target, interpolate=True).get("BROWSER_TEST_TOKEN")
            if loaded != secret:
                raise AssertionError("browser handoff value did not round-trip through python-dotenv")
            assert_plaintext_absent(
                secret,
                ("service telemetry", usage_log.read_text()),
                ("browser console", "\n".join(console_errors)),
            )
            if console_errors:
                raise AssertionError("browser reported console errors; protected diagnostics withheld")
        finally:
            if not receiver_drained:
                if receiver.poll() is None:
                    receiver.kill()
                drain_receiver_output(
                    receiver,
                    secret,
                    link_line,
                    timeout=3,
                    phase="receiver cleanup",
                )
