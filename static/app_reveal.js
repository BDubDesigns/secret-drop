import sodium from "/static/libsodium-wrappers.mjs";

const button = document.querySelector("#reveal");
const status = document.querySelector("#status");
const secretHeading = document.querySelector("#secret-heading");
const secretField = document.querySelector("#secret");
const secretActions = document.querySelector("#secret-actions");
const copyButton = document.querySelector("#copy-secret");
const hideButton = document.querySelector("#hide-secret");

const PRODUCTION_HIDE_SECONDS = 120;
const requested = Number(
  new URLSearchParams(window.location.search).get("clip") || PRODUCTION_HIDE_SECONDS
);
const HIDE_SECONDS = Number.isFinite(requested) && requested > 0
  ? Math.min(requested, PRODUCTION_HIDE_SECONDS)
  : PRODUCTION_HIDE_SECONDS;

let claimed = false; // true once the relay returned a claim result
let hideTimer = null;

function show(message, error = false) {
  status.hidden = false;
  status.style.display = "block";
  status.textContent = message;
  status.dataset.error = error ? "true" : "false";
}

function revealLink() {
  const fragment = window.location.hash.slice(1);
  const separator = fragment.indexOf(".");
  if (separator <= 0) return null;
  const id = fragment.slice(0, separator);
  const key = fragment.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(key)) {
    return null;
  }
  return { id, key };
}

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

const link = revealLink();
if (!link) {
  button.disabled = true;
  show("Open the complete reveal link provided by the agent.", true);
}

copyButton.addEventListener("click", async () => {
  if (secretField.hidden || !secretField.value) return;
  try {
    await navigator.clipboard.writeText(secretField.value);
    show("Copied. Clipboard contents are outside shh's control; hide the page when finished.");
  } catch {
    show("Copy was blocked by the browser. Select the value manually, then hide it when finished.", true);
  }
});

hideButton.addEventListener("click", () => {
  if (!secretField.hidden) {
    clearRevealedSecret();
  }
});

button.addEventListener("click", async () => {
  if (!link) return;
  button.disabled = true;
  show("Claiming and decrypting…");
  let key;
  try {
    await sodium.ready;

    // Validate the key BEFORE claiming: a malformed link must not destroy the
    // drop. The relay marks a drop claimed destructively, so a wrong key after
    // claiming is unrecoverable. Note a correct-length but wrong key remains
    // destructive by design (single-use); length validation only catches
    // truncation/corruption.
    try {
      key = sodium.from_base64(
        link.key,
        sodium.base64_variants.URLSAFE_NO_PADDING
      );
    } catch {
      button.disabled = false;
      show("This link's key is malformed. Ask the agent for a fresh link.", true);
      return;
    }
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) {
      button.disabled = false;
      show("This link's key is incomplete. Ask the agent for a fresh link.", true);
      return;
    }

    let combined;
    let plaintextBytes;
    try {
      const response = await fetch(`/api/drops/${link.id}/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
        body: "{}",
      });
      if (response.status === 202) {
        // Not delivered yet — the drop is untouched, retry is legitimate.
        show("The secret has not been delivered yet. Try again shortly.", true);
        button.disabled = false;
        return;
      }
      if (response.status === 429) {
        // Rate-limited — the drop is untouched, retry is legitimate.
        show("Too many attempts. Wait a minute and try again.", true);
        button.disabled = false;
        return;
      }
      // From here the drop is spent or spent-ish: 404 means it is gone, and any
      // 4xx/5xx/200 response means the claim was answered. Retry cannot help.
      claimed = true;
      if (response.status === 404) {
        show("This secret has already been claimed or has expired.", true);
        return;
      }
      if (!response.ok) {
        show("The relay rejected this claim.", true);
        return;
      }
      const data = await response.json();
      if (data.v !== 1 || typeof data.payload !== "string") {
        show("The relay returned an unexpected payload.", true);
        return;
      }
      combined = sodium.from_base64(
        data.payload,
        sodium.base64_variants.URLSAFE_NO_PADDING
      );
      const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
      const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);
      plaintextBytes = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
      const plaintext = sodium.to_string(plaintextBytes);

      // Remove the capability before placing plaintext into the visible UI.
      clearCapabilityFragment();
      secretField.value = plaintext;
      secretField.hidden = false;
      secretHeading.hidden = false;
      secretActions.hidden = false;
      show(`Revealed. This secret will hide in ${HIDE_SECONDS} seconds as screen/privacy hygiene.`);
      hideTimer = setTimeout(clearRevealedSecret, HIDE_SECONDS * 1000);
      secretField.focus();
    } finally {
      if (combined) sodium.memzero(combined);
      if (plaintextBytes) sodium.memzero(plaintextBytes);
    }
  } catch (error) {
    // Never re-enable retry once the claim was answered: the drop is gone.
    if (!claimed) {
      button.disabled = false;
    }
    show(error instanceof Error ? error.message : "Reveal failed.", true);
  } finally {
    if (key) sodium.memzero(key);
  }
});

// If the tab is backgrounded or navigated away, don't leave the secret sitting.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden" && !secretField.hidden) {
    clearRevealedSecret();
  }
});
window.addEventListener("pagehide", () => {
  if (!secretField.hidden) {
    clearRevealedSecret();
  }
});
