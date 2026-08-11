from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from dotenv import dotenv_values
from playwright.sync_api import expect, sync_playwright

import server


def assert_plaintext_absent(plaintext: str, *channels: tuple[str, str]) -> None:
    for channel, captured in channels:
        if plaintext in captured:
            raise AssertionError(f"{channel} contained the test plaintext") from None


def output_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def release_link(base: str, secret: str) -> str:
    result = subprocess.run(
        [sys.executable, "decrypt_to_file.py", "release", "--relay", base],
        input=secret,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError("release helper failed; protected diagnostics withheld")
    assert_plaintext_absent(
        secret,
        ("release stdout", result.stdout),
        ("release stderr", result.stderr),
    )
    line = next(
        (value for value in result.stdout.splitlines() if value.startswith("shh reveal link: ")),
        None,
    )
    if line is None:
        raise AssertionError("release helper did not emit a reveal link")
    return line.removeprefix("shh reveal link: ").strip()


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


def test_bare_root_onboards_human_and_agent(tmp_path):
    with browser_test_relay(tmp_path) as (base, _):
        console_errors: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            page.goto(base + "/", wait_until="networkidle")
            expect(page.locator("#landing")).to_be_visible()
            expect(page.locator("#delivery")).to_be_hidden()
            expect(page.get_by_text("No handoff link detected", exact=False)).to_be_visible()
            expect(page.get_by_text("Human → Agent", exact=True)).to_be_visible()
            expect(page.get_by_text("Agent → Human", exact=True)).to_be_visible()
            expect(page.locator('a[href="/agent.md"]')).to_be_visible()
            assert page.locator('a[href="https://github.com/BDubDesigns/secret-drop"]').count() >= 1
            assert page.locator('a[href="https://qcfailed.com"]').count() >= 1
            assert not console_errors
            browser.close()


def test_malformed_fragment_stays_in_landing_mode(tmp_path):
    with browser_test_relay(tmp_path) as (base, _):
        requests: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            page.on("request", lambda request: requests.append(request.url))
            page.goto(base + "/#truncated", wait_until="networkidle")
            expect(page.locator("#landing")).to_be_visible()
            expect(page.locator("#delivery")).to_be_hidden()
            expect(page.get_by_text("incomplete or invalid", exact=False)).to_be_visible()
            expect(page.get_by_text("fresh link", exact=False)).to_be_visible()
            assert page.locator("#send").is_disabled()
            assert not any(url.endswith("/payload") for url in requests)
            browser.close()


def test_landing_is_responsive_and_keyboard_reachable(tmp_path):
    with browser_test_relay(tmp_path) as (base, _):
        console_errors: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            page.goto(base + "/", wait_until="networkidle")
            expect(page.locator("#landing")).to_be_visible()
            expect(page.locator("#human-agent-title")).to_be_visible()
            expect(page.locator("#agent-human-title")).to_be_visible()
            expect(page.locator('a[href="/agent.md"]')).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

            reached_agent_link = False
            for _ in range(20):
                page.keyboard.press("Tab")
                if page.locator(":focus").get_attribute("href") == "/agent.md":
                    reached_agent_link = True
                    break
            assert reached_agent_link
            assert not console_errors
            browser.close()


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
                        expect(page.locator("#landing")).to_be_hidden()
                        expect(page.locator("#delivery")).to_be_visible()
                        expect(page.locator("#send")).to_be_enabled()
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


def test_browser_reveals_agent_released_secret_once(tmp_path):
    secret = "browser-reveal-secret-must-not-appear-in-captured-output"

    with browser_test_relay(tmp_path) as (base, _):
        # Agent publishes the secret via the release helper.
        link = release_link(base, secret)

        console_errors: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            # ?clip=1 speeds up the real clipping timer for the test. Insert the
            # query BEFORE the #fragment so it doesn't corrupt the key.
            path, _, fragment = link.partition("#")
            fast_link = f"{path}?clip=1#{fragment}"
            page.goto(fast_link, wait_until="networkidle")
            page.locator("#reveal").click()
            page.locator("#secret").wait_for(state="visible", timeout=10000)
            revealed = page.locator("#secret").input_value()
            assert revealed == secret
            assert page.locator("#secret-heading").is_visible()
            # The secret must actually clip itself, and the key-carrying
            # fragment must be removed from the URL afterwards.
            page.locator("#secret").wait_for(state="hidden", timeout=10000)
            assert page.locator("#secret").input_value() == ""
            assert "#" not in page.url
            assert "clipped" in page.locator("#status").text_content().lower()
            browser.close()

        # Second reveal attempt in a fresh page must fail (single use).
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            page.goto(link, wait_until="networkidle")
            page.locator("#reveal").click()
            # CSP forbids eval, so poll via expect() instead of wait_for_function.
            expect(page.locator("#status")).to_contain_text("already been claimed", timeout=10000)
            assert page.locator("#secret").is_hidden()
            browser.close()

        assert not console_errors, console_errors

def test_browser_truncated_key_does_not_destroy_drop(tmp_path):
    """A malformed link key must fail before claiming, leaving the drop alive."""
    secret = "truncated-key-secret"

    with browser_test_relay(tmp_path) as (base, _):
        link = release_link(base, secret)
        drop_id, key = link.split("#", 1)[1].split(".", 1)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            # Truncate the key: 43 chars -> 42 chars. Old behavior claimed the
            # drop destructively before failing to decrypt.
            bad_link = f"{base}/reveal#{drop_id}.{key[:-1]}"
            page.goto(bad_link, wait_until="networkidle")
            page.locator("#reveal").click()
            # Either validation path ("malformed" or "incomplete") must refuse
            # the claim before the relay is touched.
            expect(page.locator("#status")).to_contain_text("fresh link", timeout=10000)
            browser.close()

        # The drop must still be intact and claimable with the real key.
        import urllib.request

        req = urllib.request.Request(
            f"{base}/api/drops/{drop_id}/claim",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            assert response.status == 200, response.status
            body = json.loads(response.read())
        assert body.get("v") == 1 and isinstance(body.get("payload"), str)


def test_browser_reveal_keeps_xss_shaped_secret_inert(tmp_path):
    """HTML-like plaintext must be shown as text, never injected into the DOM."""
    payload_secret = "<script>window.__xss=2</script>"

    with browser_test_relay(tmp_path) as (base, _):
        link = release_link(base, payload_secret)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--use-gl=swiftshader"],
            )
            page = browser.new_page()
            page.goto(link, wait_until="networkidle")
            page.locator("#reveal").click()
            page.locator("#secret").wait_for(state="visible", timeout=10000)
            # The plaintext must round-trip byte-for-byte as inert text…
            assert page.locator("#secret").input_value() == payload_secret
            # …and no element outside the textarea may have been injected.
            assert page.evaluate("window.__xss === undefined")
            # The status element must not have interpreted the payload as HTML.
            assert page.locator("#status img").count() == 0
            assert page.locator("#status script").count() == 0
            browser.close()
