from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

import server


def test_browser_encrypts_and_receiver_writes_without_plaintext_leak(tmp_path):
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
    base = f"http://127.0.0.1:{httpd.server_port}"
    target = tmp_path / ".env"
    secret = "browser-test-secret-must-not-appear-in-captured-output"
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
    try:
        assert receiver.stdout is not None
        link_line = receiver.stdout.readline().strip()
        assert link_line.startswith("shh link: "), link_line
        link = link_line.removeprefix("shh link: ")

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
            page.goto(link, wait_until="networkidle")
            page.locator("#input").fill(secret)
            page.locator("#send").click()
            try:
                page.locator("#status").filter(
                    has_text="Delivered. You can close this tab."
                ).wait_for(state="attached", timeout=10000)
            except Exception as exc:
                status_text = page.locator("#status").text_content()
                raise AssertionError(
                    f"browser delivery did not complete: status={status_text!r}; errors={console_errors!r}"
                ) from exc
            assert page.locator("#status").text_content() == "Delivered. You can close this tab."
            browser.close()

        stdout, stderr = receiver.communicate(timeout=10)
        assert receiver.returncode == 0, (stdout, stderr)
        assert target.read_text() == f'BROWSER_TEST_TOKEN="{secret}"\n'
        assert secret not in stdout
        assert secret not in stderr
        assert not console_errors, console_errors
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.communicate(timeout=3)
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()
