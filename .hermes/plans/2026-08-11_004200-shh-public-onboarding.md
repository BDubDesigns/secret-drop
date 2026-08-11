# shh Public Onboarding and Agent Discovery Implementation Plan

> **For Hermes:** Brandon will manually switch to DeepSeek V4 Flash for implementation. Execute this plan sequentially on one issue branch using strict TDD. Do not merge, deploy, or mutate GitHub repository metadata without Brandon's explicit approval.

**Issue:** [#6 — feat: make shh a discoverable public secret bridge for humans and AI agents](https://github.com/BDubDesigns/secret-drop/issues/6)

**Plan author/reviewer:** Sol (`gpt-5.6-sol`)

**Implementation model:** DeepSeek V4 Flash

**Review model:** Sol, against the actual diff and execution evidence

**Base commit:** `35bb370` (`main`, reverse secret release merged)

**Goal:** Turn the bare `shh.qcfailed.com` domain into a clear, intentional onboarding page for humans and AI agents while preserving the existing fragment-based ingress and reveal protocols.

**Architecture:** Keep the stdlib Python server and small browser modules. The root response will contain both a public landing section and a hidden delivery section; `static/app.js` will validate the client-only fragment and select the correct mode without sending keys to the server. Machine-readable instructions will live as repository documents and be served through explicit allowlisted routes. Root and reveal pages will share one local stylesheet under a stricter same-origin CSP.

**Tech stack:** Python 3.12 stdlib HTTP server, PyNaCl/libsodium, plain HTML/CSS/ES modules, pytest, Playwright Chromium, Docker, GitHub Actions, Coolify.

---

## 1. Planning decisions locked for implementation

These decisions resolve issue #6's remaining ambiguity. DeepSeek should not silently replace them with a different product design.

### 1.1 Root-page mode selection

- `/` or `/index.html` with no fragment renders a useful public landing page.
- A valid existing `/#<drop_id>.<public_key>` fragment switches the page to the focused Human → Agent delivery form.
- A non-empty but malformed fragment renders the landing shell plus a clear “incomplete or invalid handoff link” message. It must not display an enabled form or make an API request.
- Existing CLI-generated links remain byte-for-byte compatible. Do not change the fragment grammar or API envelope.
- The landing page is visible by default in server-rendered HTML. The delivery section uses the native `hidden` attribute until JavaScript validates the fragment. This gives no-fragment visitors useful content even if JavaScript fails.
- Do not add a browser-side “Create a drop” action. The receiver agent must hold the ingress private key and declare the destination before the human supplies a value.

### 1.2 Agent discovery

- Create `docs/agent.md` as the canonical repository-owned agent guide.
- Serve that file at `GET /agent.md` as `text/markdown; charset=utf-8`.
- Create root-level `llms.txt` and serve it at `GET /llms.txt` as `text/plain; charset=utf-8`.
- `/llms.txt` points to `/agent.md`, GitHub, and the security model; it does not duplicate the whole guide.
- Do not add OpenAPI in this issue. The HTTP API alone is not a safe description of key ownership, stdin handling, or local decryption.
- Agent documentation must direct agents to the supported helper. It must explicitly say never to ask a human to paste a secret into chat and never to pass a literal secret through argv.

### 1.3 Visual direction

Use a restrained “quiet vault / precise developer tool” system influenced by Linear's luminance hierarchy and Ollama's restraint, without copying either brand.

- No framework, build step, external font, analytics script, image CDN, decorative stock art, or third-party runtime asset.
- System sans for prose and system monospace for commands/capability URLs.
- Near-black canvas, slightly lighter panels, whisper-thin borders, one muted mint accent reserved for interactive/security-positive states.
- No neon glow, glassmorphism, animated gradients, giant marketing typography, fake terminal chrome, or decorative padlock spam.
- CSS custom properties are the design tokens. Suggested starting values:

```css
:root {
  color-scheme: dark;
  --bg: #080a0c;
  --surface: #101419;
  --surface-raised: #161c22;
  --text: #f2f5f7;
  --text-muted: #9aa5b1;
  --text-subtle: #6f7a86;
  --border: rgba(255, 255, 255, 0.09);
  --border-strong: rgba(255, 255, 255, 0.16);
  --accent: #8bd6b2;
  --accent-strong: #a5e6c7;
  --danger: #ff9a9a;
  --warning: #e8c779;
  --focus: #b7f3d7;
  --radius-control: 8px;
  --radius-card: 12px;
  --content-wide: 1120px;
  --content-task: 720px;
}
```

- Landing mode may use `--content-wide`; active handoff modes stay narrow and task-focused.
- Desktop flow explanation: two cards or columns. Mobile: one stacked column with no horizontal overflow.
- Minimum interactive target: approximately 44px high.
- Every link and button needs a visible keyboard focus state.
- Respect `prefers-reduced-motion`; motion is optional and must never be required to understand state.

### 1.4 Shared CSS and CSP

- Create `static/app.css` and use it for both root and reveal pages.
- Remove the duplicated inline `<style>` blocks from `server.py`.
- Explicitly allowlist `app.css` in the static route with `text/css; charset=utf-8`.
- Tighten page CSP from `style-src 'unsafe-inline'` to `style-src 'self'`.
- Preserve nonce-protected module/import-map scripts, `'wasm-unsafe-eval'` inside `script-src`, `connect-src 'self'`, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'none'`, and `img-src 'none'`.
- Use no external font or image so CSP does not need to expand.

### 1.5 Reveal usability and cleanup timer

The 20-second timer is convenience hygiene, not a defense against someone who has the link or browser access.

Implement this behavior:

- Remove the key-bearing fragment with `history.replaceState` immediately after successful decryption and before exposing plaintext in the UI.
- Show explicit **Copy secret** and **Hide now** controls after reveal.
- Copy is user-initiated. Do not auto-copy. After copying, explain that clipboard contents are outside `shh`'s control; do not claim the page can securely clear the system clipboard later.
- **Hide now**, `visibilitychange` to hidden, and `pagehide` all clear the textarea, hide the secret/actions, cancel the timer, and update status without reinserting secret text into HTML.
- Use a **120-second automatic fallback**. This is long enough for normal use but still removes an abandoned foreground display.
- Preserve the public `?clip=` E2E hook as shorten-only:

```js
const PRODUCTION_HIDE_SECONDS = 120;
const requested = Number(
  new URLSearchParams(window.location.search).get("clip") || PRODUCTION_HIDE_SECONDS
);
const HIDE_SECONDS = Number.isFinite(requested) && requested > 0
  ? Math.min(requested, PRODUCTION_HIDE_SECONDS)
  : PRODUCTION_HIDE_SECONDS;
```

- UI copy must describe automatic hiding as screen/privacy hygiene, never as a security boundary.
- Preserve pre-claim validation and retry semantics: malformed/truncated keys do not claim; `202` and `429` remain retryable; terminal responses never falsely re-enable retry.

### 1.6 Public hosted-instance posture

Use consistent wording across the landing page, README, agent guide, and security documentation:

- Open source, MIT licensed, and self-hostable.
- `shh.qcfailed.com` is a best-effort public instance/demo with no account or SLA.
- The expected implementation encrypts in the client and gives the relay only opaque ciphertext.
- The operator serves the JavaScript; a compromised or malicious same-origin server can replace it and capture a future plaintext before encryption.
- Short TTLs, rate limits, storage ceilings, and one-time claims are abuse/lifecycle controls, not identity or access control.
- Do not call the hosted instance a vault or promise hostile-operator resistance.

### 1.7 GitHub metadata is post-merge work

Repository homepage/topics are remote side effects and are not represented in the PR diff.

- DeepSeek must not change them while implementing the branch.
- The PR body should list the intended metadata changes.
- After Brandon approves and the PR merges, update metadata and read it back from GitHub before closing issue #6.

---

## 2. Current repository map and change surface

### Production files to modify

- `server.py`
  - `_build_page()` at the current root-page HTML builder.
  - `_build_reveal_page()` at the reveal HTML builder.
  - `DropHandler.do_GET()` for `/agent.md`, `/llms.txt`, stylesheet MIME handling, and shared CSP.
  - Prefer a small explicit static-file map and a shared page-CSP helper; do not make the repository generally file-servable.
- `static/app.js`
  - Parse missing/valid/invalid fragment states.
  - Switch landing/delivery sections.
  - Add public agent-guide copy interaction.
  - Preserve sealed-box delivery behavior and inert text status rendering.
- `static/app_reveal.js`
  - Immediate fragment removal after successful decrypt.
  - Copy, hide, background/pagehide cleanup.
  - Bounded 120-second fallback.
  - Preserve one-time/retry/security behavior.
- `static/app.css` — create shared responsive styles and design tokens.
- `docs/agent.md` — create canonical agent instructions.
- `llms.txt` — create discovery document.
- `README.md` — generic product-first presentation, hosted demo, human/agent quick starts, links, updated reveal behavior.
- `PROJECT.md` — public product posture and Sol → DeepSeek → Sol delivery workflow; remove stale Terra/Luna process wording.
- `docs/architecture-security.md` — update personal-only framing, both-direction lifecycle, hosted-instance caveats, and reveal UI hygiene language.
- `.dockerignore` — exclude `.hermes/`, `.venv/`, and `venv/` so plans/local environments are not copied into the runtime image.

### Test files to modify

- `tests/test_handoff.py`
  - Server-rendered landing shell, docs endpoints, MIME types, static CSS, and CSP assertions.
- `tests/test_browser_e2e.py`
  - Reuse the external-relay fixture for reverse tests.
  - Bare landing, malformed-fragment, responsive, delivery-mode, reveal controls, fragment cleanup, timer clamp, and background cleanup.

### Files expected not to require production changes

- `decrypt_to_file.py` — CLI/protocol formats remain unchanged.
- `Dockerfile` — `COPY . .` already includes docs and CSS; `.dockerignore` controls unwanted build context.
- `.github/workflows/verify.yml` — existing jobs should pick up stronger tests automatically. Modify only if the new external-container tests cannot execute through the existing `SHH_RELAY_URL` contract.
- `requirements.txt` / `requirements-dev.txt` — no new dependency is justified.

---

## 3. Task-by-task implementation plan

## Task 0: Establish the approved-plan handoff and baseline

**Objective:** Start from verified `main`, preserve this plan as the durable implementation contract, and prove the baseline before changing behavior.

**Files:**
- Commit: `.hermes/plans/2026-08-11_004200-shh-public-onboarding.md`
- Modify: `.dockerignore`

**Step 1: Confirm approval before coding**

Do not proceed until Brandon has reviewed this plan and manually switched the session to DeepSeek V4 Flash.

**Step 2: Create the single issue branch**

```bash
git switch main
git pull --ff-only origin main
git switch -c feat/issue-6-public-onboarding
```

Expected: branch starts at `35bb370` unless `main` legitimately advanced; if it advanced, reread the diff and issue before proceeding.

**Step 3: Keep local/factory files out of the runtime image**

Add to `.dockerignore`:

```text
.hermes/
.venv/
venv/
```

Do not add `.hermes/plans/` to `.gitignore`; the approved plan should be reviewable and committed, just not shipped inside the container.

**Step 4: Run the untouched baseline**

```bash
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers .venv/bin/python -m pytest -q
git diff --check
```

Expected baseline: all existing tests pass (27 tests at plan time) and `git diff --check` is clean. If baseline fails, stop and diagnose before implementation.

**Step 5: Commit the plan and image-context hygiene**

```bash
git add .hermes/plans/2026-08-11_004200-shh-public-onboarding.md .dockerignore
git commit -m "docs: add issue 6 implementation plan"
```

---

## Task 1: Make every browser flow testable against the shipped container

**Objective:** Ensure the Docker CI job exercises reverse reveal and new public pages against the built container, not an accidental local server.

**Files:**
- Modify: `tests/test_browser_e2e.py`
- Production files: none

**Step 1: Refactor existing reverse tests to the shared relay fixture**

Use `browser_test_relay(tmp_path)` in:

- `test_browser_reveals_agent_released_secret_once`
- `test_browser_truncated_key_does_not_destroy_drop`
- `test_browser_reveal_keeps_xss_shaped_secret_inert`

Remove each test's duplicated `make_server` / thread / shutdown block. Add a narrowly scoped helper such as:

```python
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
```

Do not include the synthetic plaintext in assertion messages or diagnostics.

**Step 2: Run the existing browser tests locally**

```bash
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest tests/test_browser_e2e.py -q
```

Expected: the same existing browser behaviors pass before production code changes.

**Step 3: Prove all browser tests use an external container**

```bash
docker build -t shh:issue-6-baseline .
mkdir -p /tmp/shh-issue-6-data
docker rm -f shh-issue-6 2>/dev/null || true
docker run -d --name shh-issue-6 \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:18899:8899 \
  -v /tmp/shh-issue-6-data:/app/data \
  shh:issue-6-baseline
curl --fail --retry 30 --retry-delay 1 http://127.0.0.1:18899/healthz
SHH_RELAY_URL=http://127.0.0.1:18899 \
SHH_USAGE_LOG=/tmp/shh-issue-6-data/usage.jsonl \
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest tests/test_browser_e2e.py -q
docker rm -f shh-issue-6
```

Expected: every browser test passes against the container. If a test still starts a local server, the refactor is incomplete.

**Step 4: Commit test-harness improvement**

```bash
git add tests/test_browser_e2e.py
git commit -m "test: run all browser flows against external relay"
```

---

## Task 2: Add canonical machine-readable agent onboarding

**Objective:** Let an agent given only `https://shh.qcfailed.com` discover the supported helper workflow without reverse-engineering JavaScript.

**Files:**
- Create: `docs/agent.md`
- Create: `llms.txt`
- Modify: `server.py`
- Test: `tests/test_handoff.py`

**Step 1 — RED: Add endpoint/document contract tests**

Add focused tests before routes/files:

```python
def test_agent_onboarding_documents_are_served(app_server):
    base, _ = app_server

    with urlopen(base + "/agent.md", timeout=3) as response:
        agent = response.read().decode()
        agent_type = response.headers.get_content_type()
        agent_cache = response.headers["Cache-Control"]

    with urlopen(base + "/llms.txt", timeout=3) as response:
        llms = response.read().decode()
        llms_type = response.headers.get_content_type()

    assert agent_type == "text/markdown"
    assert agent_cache == "no-store"
    assert "decrypt_to_file.py receive" in agent
    assert "decrypt_to_file.py release" in agent
    assert "stdin" in agent.lower()
    assert "never ask" in agent.lower()
    assert "--secret" not in agent
    assert "https://github.com/BDubDesigns/secret-drop" in agent
    assert "/agent.md" in llms
    assert "docs/architecture-security.md" in llms
    assert llms_type == "text/plain"
```

Add a second test asserting a near-miss path such as `/agent.md/extra` remains 404 JSON; do not introduce generic filesystem serving.

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_handoff.py::test_agent_onboarding_documents_are_served -v
```

Expected RED: 404 because the endpoints do not exist.

**Step 2 — GREEN: Write `docs/agent.md`**

Required sections:

1. Purpose and explicit “never paste a secret into chat” rule.
2. Trust model and hosted-instance posture.
3. Clone/install commands using Python 3.12+ and `requirements.txt`.
4. Human → Agent exact receive command:

```bash
.venv/bin/python decrypt_to_file.py receive \
  --relay https://shh.qcfailed.com \
  --name EXPECTED_VARIABLE \
  --target /absolute/path/to/.env
```

5. Expected `shh link:` output and instruction to send the complete clickable fragment URL to the human.
6. Agent → Human stdin-only release commands from a file and environment variable; never show a literal secret in the command.
7. Expected `shh reveal link:` output and live bearer-capability warning.
8. Exit-code table reflecting current code:
   - receive: `0` success; `2` input validation; `3` relay/invalid response; `4` expiry/unavailable; `5` decryption failure; `6` target/value validation.
   - release: `0` confirmed publish; `2` input validation; `3` failed/rejected; `4` upload ambiguous with recovery link preserved.
9. Links to README, architecture/security, and self-hosting.
10. “Use the supported helper; do not guess/reimplement the crypto protocol from raw API calls.”

Do not claim that the operator cannot replace the page JavaScript.

**Step 3 — GREEN: Write `llms.txt`**

Keep it short. It should contain:

```text
# shh

shh is an open-source, self-hostable, one-time secret bridge between humans and AI agents.

Agent instructions: https://shh.qcfailed.com/agent.md
Source: https://github.com/BDubDesigns/secret-drop
Security model: https://github.com/BDubDesigns/secret-drop/blob/main/docs/architecture-security.md

Use the supported helper. Never ask a human to paste a secret into chat and never put a literal secret in argv.
```

**Step 4 — GREEN: Add exact server routes**

At module scope, define explicit document paths, for example:

```python
AGENT_GUIDE_PATH = BASE_DIR / "docs" / "agent.md"
LLMS_PATH = BASE_DIR / "llms.txt"
```

In `do_GET`, before the generic 404:

```python
if path == "/agent.md":
    self._send(200, AGENT_GUIDE_PATH.read_bytes(), "text/markdown; charset=utf-8")
    return
if path == "/llms.txt":
    self._send(200, LLMS_PATH.read_bytes(), "text/plain; charset=utf-8")
    return
```

Fail closed if a packaged file is absent; do not accept user-controlled file paths.

**Step 5: Verify GREEN and container packaging**

```bash
.venv/bin/python -m pytest tests/test_handoff.py -q
docker build -t shh:issue-6-docs .
docker run --rm --entrypoint sh shh:issue-6-docs -c \
  'test -f /app/docs/agent.md && test -f /app/llms.txt && test ! -e /app/.hermes'
```

Expected: tests pass; documents are in the image; `.hermes` is absent.

**Step 6: Commit**

```bash
git add docs/agent.md llms.txt server.py tests/test_handoff.py
git commit -m "feat: add machine-readable agent onboarding"
```

---

## Task 3: Extract a shared visual system and tighten CSP

**Objective:** Make root and reveal pages maintainable and intentionally styled without adding dependencies or weakening CSP.

**Files:**
- Create: `static/app.css`
- Modify: `server.py`
- Test: `tests/test_handoff.py`

**Step 1 — RED: Extend page/static security tests**

Add or extend tests to assert:

```python
with urlopen(base + "/", timeout=3) as response:
    root_page = response.read().decode()
    root_csp = response.headers["Content-Security-Policy"]
with urlopen(base + "/reveal", timeout=3) as response:
    reveal_page = response.read().decode()
    reveal_csp = response.headers["Content-Security-Policy"]
with urlopen(base + "/static/app.css", timeout=3) as response:
    css = response.read().decode()
    css_type = response.headers.get_content_type()

assert '/static/app.css' in root_page
assert '/static/app.css' in reveal_page
assert '<style>' not in root_page
assert '<style>' not in reveal_page
assert "style-src 'self'" in root_csp
assert "'unsafe-inline'" not in root_csp
assert root_csp == reveal_csp or both preserve the same directive set
assert css_type == "text/css"
assert "--accent:" in css
```

Run the focused test and confirm RED due to missing CSS/current inline styles.

**Step 2 — GREEN: Add an explicit typed static map**

Replace the one-line static allowlist with a readable map containing path and MIME type:

```python
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
```

Keep filename lookup exact. Unknown `/static/*` remains 404 JSON.

**Step 3 — GREEN: Extract page CSS**

Create `static/app.css` using the locked tokens. Include styles for:

- shared page/header/footer shell;
- narrow `.task-shell` and wide `.landing-shell`;
- hero/lede;
- status badges (`open source`, `MIT`, `self-hostable`, `blind relay`);
- two flow cards and step numbering;
- agent-guide callout/code row;
- delivery/reveal panels;
- textarea, buttons, secondary buttons, links, status, telemetry note, trust disclosure;
- `[hidden] { display: none !important; }` as a defensive explicit rule;
- keyboard `:focus-visible`;
- responsive breakpoint near `720px`;
- `prefers-reduced-motion` fallback.

Do not reference external URLs or images from CSS.

**Step 4 — GREEN: Update both HTML builders**

- Link `/static/app.css` in `<head>`.
- Remove inline `<style>` blocks.
- Use semantic `<header>`, `<main>`, `<section>`, `<footer>` and associated labels.
- Preserve existing control IDs until the relevant JS task changes them.
- Keep all secret rendering in textarea `.value` or `textContent`, never `innerHTML`.

**Step 5 — GREEN: Share CSP generation**

Extract a small helper such as `_page_csp(nonce: str) -> str` to remove root/reveal duplication. Set `style-src 'self'` and preserve all other current protections.

Run:

```bash
.venv/bin/python -m pytest tests/test_handoff.py -q
node --check static/app.js
node --check static/app_reveal.js
git diff --check
```

Expected: all server tests pass, both browser modules parse, and the diff is clean.

**Step 6: Commit**

```bash
git add static/app.css server.py tests/test_handoff.py
git commit -m "feat: add shared shh visual system"
```

---

## Task 4: Implement useful bare-domain onboarding and safe mode switching

**Objective:** Make `/` self-explanatory while preserving the current ingress link and crypto flow.

**Files:**
- Modify: `server.py`
- Modify: `static/app.js`
- Modify: `static/app.css`
- Test: `tests/test_browser_e2e.py`
- Test: `tests/test_handoff.py`

**Step 1 — RED: Add bare-root Playwright test**

Use `browser_test_relay(tmp_path)` so Docker CI runs this against the built image:

```python
def test_bare_root_onboards_human_and_agent(tmp_path):
    with browser_test_relay(tmp_path) as (base, _):
        console_errors = []
        # launch browser using existing safe args and error listeners
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
```

Confirm RED: landing elements do not exist.

**Step 2 — RED: Add malformed-fragment behavior test**

Navigate to `base + "/#truncated"` and assert:

- landing remains visible;
- delivery form remains hidden/disabled;
- message says the link is incomplete/invalid and asks for a fresh link;
- no request is made to `/payload` (track page requests or assert relay state remains unchanged when using a real pending drop with malformed key).

This test must not destructively consume or submit to a real drop.

**Step 3 — RED: Strengthen valid ingress E2E**

Before filling the secret in the existing end-to-end test, assert:

```python
expect(page.locator("#landing")).to_be_hidden()
expect(page.locator("#delivery")).to_be_visible()
expect(page.locator("#send")).to_be_enabled()
```

This existing test remains the protocol proof through browser encryption, relay, receiver decryption, and `.env` write.

**Step 4 — GREEN: Render the landing and delivery sections**

`_build_page()` should include:

- Compact brand header: `shh` plus an accurate one-line descriptor.
- Hero:
  - “A one-time secret bridge for humans and AI agents.”
  - Best-effort hosted/self-hosted wording.
  - status badges.
- Empty state: “No handoff link detected. Ask your agent to create one.”
- Two flow cards:
  - Human → Agent: agent creates link → human encrypts in browser → receiver claims/writes.
  - Agent → Human: agent publishes ciphertext → human receives reveal link → browser claims/decrypts once.
- Agent callout:
  - visible `/agent.md` URL;
  - normal anchor to `/agent.md`;
  - optional **Copy agent URL** button whose content is public, not secret.
- Trust summary and telemetry disclosure.
- Footer links:
  - GitHub repository;
  - architecture/security document on GitHub;
  - README deployment/self-hosting anchor on GitHub;
  - `https://qcfailed.com` with “Built by Brandon Werner” wording.
- Hidden focused `#delivery` section containing the existing textarea/button/status and accurate TTL copy.

Use normal text nodes. Do not build content with `innerHTML` in JavaScript.

**Step 5 — GREEN: Make fragment parsing return an explicit state**

Refactor `receiverLink()` into behavior equivalent to:

```js
function receiverLink() {
  const fragment = window.location.hash.slice(1);
  if (!fragment) return { state: "missing" };
  const separator = fragment.indexOf(".");
  if (separator <= 0) return { state: "invalid" };
  const id = fragment.slice(0, separator);
  const publicKey = fragment.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(publicKey)) {
    return { state: "invalid" };
  }
  return { state: "valid", id, publicKey };
}
```

Then:

- missing → landing visible, normal no-link message;
- invalid → landing visible, invalid-link alert;
- valid → landing hidden, delivery visible, sender enabled.

Keep libsodium and the payload request unchanged. Do not clear the ingress fragment before delivery; it contains only the drop ID and receiver public key, not a decryption capability.

**Step 6 — GREEN: Add resilient public URL copy**

If adding a copy button, use `navigator.clipboard.writeText` only after a user click. Provide a graceful status if clipboard permission is unavailable; the URL remains selectable and linked. Never use the secret textarea or a secret clipboard operation in `app.js`.

**Step 7 — RED/GREEN: Add mobile layout test**

Create a browser page with a `390 × 844` viewport. Assert:

- landing hero and both flow cards are visible/stacked;
- agent guide link is reachable;
- `document.documentElement.scrollWidth <= window.innerWidth`;
- keyboard Tab reaches the primary links/buttons with visible focus styling (DOM focus assertion; visual focus is confirmed later by screenshots).

Run:

```bash
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest \
  tests/test_browser_e2e.py::test_bare_root_onboards_human_and_agent \
  tests/test_browser_e2e.py::test_browser_encrypts_and_receiver_writes_without_plaintext_leak \
  -v
```

Expected: focused tests and full ingress flow pass with no console/page errors.

**Step 8: Commit**

```bash
git add server.py static/app.js static/app.css tests/test_browser_e2e.py tests/test_handoff.py
git commit -m "feat: add human and agent landing experience"
```

---

## Task 5: Replace the 20-second reveal race with explicit, bounded hygiene

**Objective:** Improve normal reveal usability while reducing URL capability exposure immediately after a successful claim.

**Files:**
- Modify: `server.py`
- Modify: `static/app_reveal.js`
- Modify: `static/app.css`
- Test: `tests/test_browser_e2e.py`

**Step 1 — RED: Require immediate fragment removal while plaintext is still visible**

Modify `test_browser_reveals_agent_released_secret_once` so that immediately after `#secret` becomes visible it asserts:

```python
assert page.locator("#secret").input_value() == secret
assert "#" not in page.url
expect(page.locator("#copy-secret")).to_be_visible()
expect(page.locator("#hide-secret")).to_be_visible()
```

This must happen before waiting for the auto-hide timer. Confirm RED because current code removes the fragment only in `clipNow()`.

**Step 2 — RED: Test explicit hide**

Using a fresh synthetic release link:

1. Reveal.
2. Click `#hide-secret`.
3. Assert textarea value is empty and hidden.
4. Assert action controls are hidden.
5. Assert status says the secret was hidden/cleared without containing plaintext.

**Step 3 — RED: Test explicit copy**

Use a Playwright browser context granted clipboard read/write permission for the local origin. Reveal a synthetic value, click `#copy-secret`, and assert the clipboard equals the synthetic value. Assert the UI explains that clipboard contents are outside `shh`'s control.

Do not include the synthetic plaintext in custom failure messages or captured diagnostics.

If Chromium clipboard permission is unreliable in CI, keep the production implementation and test the successful user-visible status while separately stubbing only the browser clipboard API through an init script. Do not weaken application CSP to make the test work.

**Step 4 — RED: Test page-exit/background cleanup**

After reveal, dispatch a real `pagehide` event from Playwright and assert the field/actions clear. Keep the existing `visibilitychange` production listener; browser control of `visibilityState` is inconsistent, so `pagehide` is the stable automated assertion and manual QA covers tab backgrounding.

**Step 5 — RED: Test the bounded timer hook**

- Existing fast path: use `?clip=0.2#fragment` and assert automatic cleanup occurs quickly.
- Clamp path: use a fresh link with `?clip=999999#fragment`, reveal, and assert status describes the production 120-second fallback rather than 999999 seconds. Do not wait 120 seconds.

Confirm the query appears before the fragment.

**Step 6 — GREEN: Add reveal controls to HTML**

After the secret textarea, add an initially hidden action group:

```html
<div id="secret-actions" class="button-row" hidden>
  <button id="copy-secret" type="button">Copy secret</button>
  <button id="hide-secret" class="button-secondary" type="button">Hide now</button>
</div>
```

Update heading/copy from “will be clipped shortly” to plain language such as “Revealed secret.” Use `aria-describedby` where helpful.

**Step 7 — GREEN: Refactor reveal cleanup into explicit helpers**

Use narrowly scoped helpers:

```js
function clearCapabilityFragment() {
  if (window.location.hash) {
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
}

function clearRevealedSecret(message = "Secret hidden. You can close this tab.") {
  if (hideTimer !== null) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
  secretField.value = "";
  secretField.hidden = true;
  secretHeading.hidden = true;
  secretActions.hidden = true;
  show(message);
}
```

After successful decryption and buffer cleanup:

1. Clear fragment.
2. Assign plaintext through `secretField.value`.
3. Show heading/actions.
4. Start bounded fallback timer.
5. Move focus to the revealed field or action group without selecting/copying automatically.

Do not use `innerHTML`.

**Step 8 — GREEN: Implement user-initiated copy safely**

```js
copyButton.addEventListener("click", async () => {
  if (secretField.hidden || !secretField.value) return;
  try {
    await navigator.clipboard.writeText(secretField.value);
    show("Copied. Clipboard contents are outside shh's control; hide the page when finished.");
  } catch {
    show("Copy was blocked by the browser. Select the value manually, then hide it when finished.", true);
  }
});
```

Never log or include the value in status/errors.

**Step 9 — GREEN: Bound timer and preserve claim semantics**

- Set production fallback to 120 seconds.
- Clamp `?clip=` with `Math.min` as specified in §1.5.
- `202` and `429` continue to re-enable reveal without clearing the fragment.
- Malformed/truncated key paths continue to refuse the claim.
- Once a response becomes terminal/claimed, never imply retry will work.
- Zero the decoded key in all paths where it is no longer needed. A per-click `finally` block is preferable; retry can decode the fragment again on the next click.
- Preserve zeroing of combined ciphertext/plaintext byte buffers where libsodium permits it. JavaScript strings cannot be guaranteed zeroed; document no stronger claim.

**Step 10: Run focused and full browser tests**

```bash
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest tests/test_browser_e2e.py -q
node --check static/app_reveal.js
git diff --check
```

Expected: reveal, single-use, malformed-key non-consumption, XSS-shaped inert rendering, copy/hide, pagehide, immediate fragment cleanup, timer fallback, and ingress all pass.

**Step 11: Commit**

```bash
git add server.py static/app_reveal.js static/app.css tests/test_browser_e2e.py
git commit -m "feat: improve one-time reveal controls"
```

---

## Task 6: Align README, project brief, and security documentation

**Objective:** Make public positioning and operational instructions accurate without weakening caveats.

**Files:**
- Modify: `README.md`
- Modify: `PROJECT.md`
- Modify: `docs/architecture-security.md`
- Review: `docs/agent.md`
- Review: `llms.txt`

**Step 1: Rewrite README opening and navigation**

The first screen of the README should contain:

- Generic product pitch before Brandon/Hermes origin story.
- Live instance: `https://shh.qcfailed.com` with best-effort disclaimer.
- Agent guide: `https://shh.qcfailed.com/agent.md`.
- Human → Agent and Agent → Human quick starts.
- Links to architecture/security and self-hosting.
- Accurate badges/claims only; do not call the same-origin hosted page compromise-resistant.

Keep exact stdin-only release examples. Do not introduce a literal example secret in argv or shell history.

**Step 2: Update reveal behavior documentation**

Replace “auto-clipped after a few seconds” with:

- fragment removed immediately after successful decryption;
- Copy and Hide controls;
- background/page-exit clearing;
- 120-second fallback as convenience hygiene;
- reveal link is still a live bearer capability before claim.

**Step 3: Update `PROJECT.md`**

- Position `shh` as open-source/self-hostable with a best-effort hosted instance.
- Preserve the original Hermes motivation as project history, not product scope.
- Replace stale Terra/Luna delivery process with:
  - Sol issue/plan;
  - Brandon review/model switch;
  - DeepSeek V4 Flash implementation;
  - execution evidence;
  - Sol diff/CI review;
  - Brandon merge approval;
  - retrospective/skill promotion.
- Keep one issue, one branch, one PR, and no auto-merge.

**Step 4: Update `docs/architecture-security.md`**

- Rename personal-only framing where it is no longer accurate.
- Preserve explicit same-origin JavaScript compromise limitation.
- Describe the public hosted instance as unauthenticated/best-effort and the repository as self-hostable.
- Keep telemetry fields/retention disclosure and advise legal/privacy review before expanding collection or making stronger service claims.
- Update reverse-flow text from 20-second clipping to explicit controls + 120-second hygiene fallback.
- State that Copy intentionally moves plaintext into a system clipboard outside the page's control.
- Do not alter cryptographic primitive descriptions or protocol state machine unless code changed them (this plan does not).

**Step 5: Check documentation consistency mechanically**

Run a small read-only Python check or manual search to confirm:

```text
No “Terra plans” / “Luna implements” remains.
No release example uses --secret.
No doc says the relay operator is cryptographically unable to alter served JavaScript.
All public URLs use shh.qcfailed.com, not ssh.qcfailed.com.
All local Markdown links resolve to existing files/anchors where practical.
```

Suggested commands:

```bash
python3 - <<'PY'
from pathlib import Path
text = "\n".join(p.read_text() for p in [
    Path("README.md"), Path("PROJECT.md"),
    Path("docs/architecture-security.md"), Path("docs/agent.md"),
    Path("llms.txt"),
])
assert "Terra plans" not in text
assert "Luna implements" not in text
assert "ssh.qcfailed.com" not in text
assert "--secret" not in Path("docs/agent.md").read_text()
print("documentation consistency checks passed")
PY
```

The heredoc is an implementation verification command, not a file-writing mechanism.

**Step 6: Commit**

```bash
git add README.md PROJECT.md docs/architecture-security.md docs/agent.md llms.txt
git commit -m "docs: present shh as a public agent secret bridge"
```

---

## Task 7: Complete local, container, visual, and security verification

**Objective:** Produce real evidence before opening the PR.

**Files:**
- No new production files expected.
- Temporary screenshots: `/tmp/shh-issue-6-preview/` (do not commit).

**Step 1: Mechanical checks**

```bash
git diff --check origin/main...HEAD
node --check static/app.js
node --check static/app_reveal.js
python3 -m py_compile server.py decrypt_to_file.py \
  tests/test_handoff.py tests/test_browser_e2e.py
```

Expected: zero output from `git diff --check`; JavaScript/Python checks exit 0.

**Step 2: Full local suite**

```bash
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest -v
```

Expected: all tests pass. Record the actual final count in the PR body; do not copy the old 27-test count after adding tests.

**Step 3: Build and inspect the exact runtime image**

```bash
docker build -t shh:issue-6 .
docker run --rm --entrypoint sh shh:issue-6 -c '
  test -f /app/static/app.css &&
  test -f /app/docs/agent.md &&
  test -f /app/llms.txt &&
  test ! -e /app/.hermes &&
  test ! -e /app/.venv &&
  test ! -e /app/tests
'
```

Expected: all checks exit 0.

**Step 4: Run the full browser suite against the image**

```bash
rm -rf /tmp/shh-issue-6-data
mkdir -p /tmp/shh-issue-6-data
docker rm -f shh-issue-6 2>/dev/null || true
docker run -d --name shh-issue-6 \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:18899:8899 \
  -v /tmp/shh-issue-6-data:/app/data \
  shh:issue-6
curl --fail --retry 30 --retry-delay 1 http://127.0.0.1:18899/healthz
curl --fail http://127.0.0.1:18899/agent.md >/dev/null
curl --fail http://127.0.0.1:18899/llms.txt >/dev/null
SHH_RELAY_URL=http://127.0.0.1:18899 \
SHH_USAGE_LOG=/tmp/shh-issue-6-data/usage.jsonl \
PLAYWRIGHT_BROWSERS_PATH=/opt/data/.pw-browsers \
  .venv/bin/python -m pytest tests/test_browser_e2e.py -q
```

Expected: all browser tests—including landing and reverse reveal—exercise the container and pass.

**Step 5: Check container logs without leaking synthetic plaintext**

Use the same protected pattern as CI: compare captured logs against known synthetic test values and withhold the logs if a match occurs. Do not print any real credential or live reveal link.

**Step 6: Capture human-review previews**

Using the local container and synthetic-only drops, capture:

1. Bare landing at `1440 × 900`.
2. Bare landing at `390 × 844`.
3. Valid ingress delivery mode.
4. Reveal page before claim.
5. Reveal page after decrypt with a clearly synthetic non-secret value.

Save under `/tmp/shh-issue-6-preview/`. Check each screenshot visually with `vision_analyze` or `browser_vision` for:

- hierarchy and clarity;
- no disabled-form confusion on bare root;
- intentional brand treatment;
- readable trust/telemetry copy;
- no mobile overflow;
- clear active-task focus;
- visible keyboard focus;
- no accidental plaintext in unrelated UI.

Deliver screenshots to Brandon before requesting merge. Screenshots are evidence, not a substitute for browser assertions.

**Step 7: Stop local container**

```bash
docker rm -f shh-issue-6
```

**Step 8: Final branch review**

```bash
git status --short --branch
git log --oneline --decorate origin/main..HEAD
git diff --stat origin/main...HEAD
git diff --check origin/main...HEAD
```

Expected: only intended commits/files; clean working tree; no secret material, `.env`, telemetry log, browser cache, screenshots, or local venv committed.

---

## Task 8: Open one PR and hand it back to Sol

**Objective:** Produce a reviewable implementation artifact without merging it.

**Step 1: Push the single issue branch**

```bash
git push -u origin feat/issue-6-public-onboarding
```

**Step 2: Open one PR**

Suggested title:

```text
feat: add public shh onboarding and agent discovery
```

PR body must include:

- `Closes #6`.
- Link/path to this plan.
- Product summary.
- Security invariants explicitly preserved.
- Reveal timer decision and rationale.
- Exact local test commands and actual pass counts.
- Docker image/container E2E result.
- Screenshot/preview evidence.
- GitHub Actions status once available.
- Deferred post-merge metadata actions:
  - homepage `https://shh.qcfailed.com`;
  - topics `ai-agents`, `e2ee`, `secrets`, `libsodium`, `self-hosted`.
- Confirmation that no production credential was used in testing.

Do not auto-merge.

**Step 3: Wait for both GitHub Actions jobs**

Required green jobs:

- Python and browser tests.
- Docker image and container handoff.

Do not merge around a failure or assume local tests make CI irrelevant.

**Step 4: Sol review**

Switch to Sol and review:

- issue #6;
- this plan;
- actual PR diff;
- test code quality and whether RED behavior was genuinely missing;
- CI logs/status;
- visual screenshots;
- CSP/header behavior;
- live-link capability handling;
- docs/CLI consistency;
- container packaging.

Treat DeepSeek's “done” summary as unverified. Sol must reproduce material checks or inspect primary evidence.

**Step 5: DeepSeek fixes findings**

Switch back only if needed, apply fixes on the same branch/PR, rerun all relevant tests, and repeat Sol review until approved.

---

## Task 9: Brandon-approved merge, metadata, deployment, and live proof

**Objective:** Close issue #6 only after code, repository presentation, and production behavior are verified.

This task begins only after Brandon explicitly approves merge.

**Step 1: Squash-merge the PR**

Read back the PR head SHA and green checks immediately before merging. Squash merge only if they still match the reviewed state.

**Step 2: Update GitHub repository metadata**

Set and then read back:

- Homepage: `https://shh.qcfailed.com`
- Topics:
  - `ai-agents`
  - `e2ee`
  - `secrets`
  - `libsodium`
  - `self-hosted`

Preserve any legitimate topics added meanwhile; do not blindly replace concurrent changes.

**Step 3: Wait for Coolify auto-deploy**

Do not equate a successful merge with a successful deployment. Poll production until the new distinguishable artifacts appear:

```bash
curl --fail https://shh.qcfailed.com/healthz
curl --fail https://shh.qcfailed.com/agent.md
curl --fail https://shh.qcfailed.com/llms.txt
curl --fail https://shh.qcfailed.com/static/app.css
```

Confirm the live CSS/JS hashes match merged `main` where files are deterministic.

**Step 4: Production synthetic smoke test**

Use synthetic non-secret values only:

- bare domain shows landing and no active delivery form;
- `/agent.md` and `/llms.txt` render exact merged content;
- Human → Agent live synthetic delivery writes only to a temporary approved `.env` target and never prints plaintext;
- Agent → Human live synthetic release decrypts once;
- fragment disappears immediately while value remains visible;
- Copy and Hide controls function;
- second claim is rejected;
- no console/page errors;
- mobile viewport has no horizontal overflow.

Protect diagnostics exactly as existing tests do. Do not expose a live reveal link in chat or retain it after the smoke test.

**Step 5: Close the factory loop with a retrospective**

Add a short issue or PR comment using this template:

```markdown
## Hermes factory retrospective

- Plan steps DeepSeek followed without clarification:
- Plan ambiguities or missing context:
- Deviations from the approved plan and why:
- Tests/verification that caught real defects:
- Environment/tooling friction:
- Sol review findings that the implementation model missed:
- Repo-specific lesson to preserve in project docs:
- Cross-project workflow lesson worth promoting to the Hermes software-factory skill:
- Workflow change for the next issue:
```

Do not save temporary progress, PR numbers, or commit SHAs as always-on memory. Promote only recurring class-level procedures to a reusable skill; keep `shh`-specific decisions in this repository.

**Step 6: Cleanup**

- Confirm issue #6 closed through `Closes #6` or close it after all acceptance criteria are verified.
- Delete merged feature branch locally/remotely.
- Update local `main`.
- Remove temporary containers, data, and screenshots.

---

## 4. Acceptance-criteria traceability

| Issue #6 acceptance criterion | Planned proof |
|---|---|
| Bare `/` renders onboarding | Task 4 Playwright bare-root test + desktop/mobile screenshots |
| Both directions and agent initiation explained | Task 4 content assertions + visual review |
| GitHub/security/self-host/agent/portfolio links | Task 4 DOM href assertions |
| `/agent.md` sufficient without repo discovery | Task 2 endpoint/content contract + Sol documentation review |
| `/llms.txt` discovery | Task 2 endpoint/content contract + container curl |
| Existing ingress compatible | Existing full browser → relay → receiver → `.env` E2E, strengthened in Task 4 |
| Existing reverse compatible | Existing release → claim → browser decrypt → second rejection E2E, externalized in Task 1 |
| Immediate fragment removal | Task 5 assertion while plaintext remains visible |
| Copy/Hide/background cleanup | Task 5 Playwright tests |
| Accurate trust/hosted wording | Tasks 2, 4, and 6 review |
| Mobile/keyboard | Task 4 responsive/keyboard test + screenshots |
| README and metadata | Task 6 diff + Task 9 GitHub API readback |
| Security/CSP/privacy regressions absent | Existing suite + Task 3 CSP tests + Sol review |
| Full local suite | Task 7 pytest output |
| Python/browser Actions green | Task 8 GitHub check status |
| Docker/container Actions green | Task 1 external fixture + Task 8 GitHub check status |
| Production synthetic smoke | Task 9 live browser/helper proof |

---

## 5. Risks and mitigations

### Fragment-mode regression

**Risk:** Landing logic accidentally hides or disables valid existing ingress links.

**Mitigation:** The real CLI-generated ingress E2E asserts mode state before delivering and remains byte-format compatible.

### Destructive reveal regression

**Risk:** UI refactor re-enables retry after a consuming response or claims with malformed key material.

**Mitigation:** Preserve existing state transition comments and tests for malformed key non-consumption, 202/429 retry, single use, and second-claim rejection. Add controls only after successful decrypt.

### Clipboard overclaim

**Risk:** Copy control suggests the page can protect or later clear the OS clipboard.

**Mitigation:** Copy is explicit, no auto-copy, and UI/docs state clipboard contents are outside `shh`'s control.

### CSP breakage

**Risk:** Moving CSS or changing page markup blocks libsodium WASM/import maps.

**Mitigation:** Keep nonce/import map and `'wasm-unsafe-eval'` inside `script-src`; test headers, browser console, real sealed-box ingress, and real SecretBox reveal.

### Agent-document drift

**Risk:** `/agent.md` becomes stale relative to CLI flags/exit codes.

**Mitigation:** Canonical file lives in repo; tests assert supported commands, stdin-only behavior, no `--secret`, and core URLs. Sol compares docs to `decrypt_to_file.py` during review.

### Public-service expectation creep

**Risk:** Better onboarding is interpreted as accounts/SLA/hostile-operator safety.

**Mitigation:** Repeated best-effort/self-hosted/same-origin wording; no auth, database, analytics, billing, or API expansion.

### Runtime-image bloat or leakage

**Risk:** `COPY . .` ships plans, local venvs, tests, or artifacts.

**Mitigation:** Extend `.dockerignore` and inspect image contents in Task 7.

### Metadata changed before approval

**Risk:** Repository homepage/topics change outside PR review.

**Mitigation:** Defer to Task 9 after explicit merge approval and verify readback.

### Visual redesign becomes framework scope creep

**Risk:** Implementation model introduces npm/Vite/framework dependencies for a small static UI.

**Mitigation:** Locked architecture, no new dependency, one shared CSS file, plain modules, exact non-goals.

---

## 6. Rollback strategy

The protocol and payload formats do not change, so in-flight links remain compatible through this release.

If pre-merge verification fails:

- Fix or revert individual branch commits; do not merge.
- Keep issue #6 open with the failing evidence.

If production presentation/docs fail after merge:

- Create a normal revert PR for the merged squash commit; do not force-push `main`.
- Coolify redeploys the previous known-good application.
- Existing ingress/reveal links remain protocol-compatible because API and fragment formats were unchanged.

If only GitHub metadata is wrong:

- Restore the previous homepage (`None` at plan time) and previous topics (empty at plan time), but read current values first to avoid overwriting concurrent legitimate changes.

If the reveal control change is the only regression:

- Revert the reveal UI commit through a reviewed PR while retaining landing/docs improvements if the commit history allows a clean targeted revert.
- Do not claim that restoring the 20-second timer fixes link-race security; it only restores prior UI behavior.

---

## 7. Definition of done

This issue is not done when the page “looks better.” It is done only when:

1. The approved plan was implemented on one issue branch and one PR.
2. No protocol or trust-boundary claim drifted.
3. Bare-domain, ingress, reveal, docs, responsive, CSP, and privacy behaviors have automated coverage.
4. Full local and external-container suites pass.
5. Both GitHub Actions jobs are green against the reviewed head SHA.
6. Sol approves the actual diff and evidence.
7. Brandon previews the UI and explicitly approves merge.
8. The merged deployment is distinguished and tested live with synthetic values.
9. GitHub homepage/topics are updated and read back.
10. The retrospective records concrete model-handoff and verification lessons for the next Hermes factory cycle.
