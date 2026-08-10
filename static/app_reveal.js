import sodium from "/static/libsodium-wrappers.mjs";

const button = document.querySelector("#reveal");
const status = document.querySelector("#status");
const secretHeading = document.querySelector("#secret-heading");
const secretField = document.querySelector("#secret");

const CLIP_SECONDS = 20;

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

const link = revealLink();
if (!link) {
  button.disabled = true;
  show("Open the complete reveal link provided by the agent.", true);
}

button.addEventListener("click", async () => {
  if (!link) return;
  button.disabled = true;
  show("Claiming and decrypting…");
  try {
    await sodium.ready;
    const response = await fetch(`/api/drops/${link.id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      body: "{}",
    });
    if (response.status === 202) {
      show("The secret has not been delivered yet. Try again shortly.", true);
      button.disabled = false;
      return;
    }
    if (response.status === 404) {
      show("This secret has already been claimed or has expired.", true);
      return;
    }
    if (response.status === 429) {
      show("Too many attempts. Wait a minute and try again.", true);
      button.disabled = false;
      return;
    }
    if (!response.ok) {
      show("The relay rejected this claim.", true);
      button.disabled = false;
      return;
    }
    const data = await response.json();
    if (data.v !== 1 || typeof data.payload !== "string") {
      show("The relay returned an unexpected payload.", true);
      return;
    }
    const combined = sodium.from_base64(
      data.payload,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES);
    const key = sodium.from_base64(
      link.key,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const plaintext = sodium.to_string(
      sodium.crypto_secretbox_open_easy(ciphertext, nonce, key)
    );
    secretField.value = plaintext;
    secretField.hidden = false;
    secretHeading.hidden = false;
    show(`Revealed. This secret will be clipped in ${CLIP_SECONDS} seconds.`);
    setTimeout(() => {
      secretField.value = "";
      secretField.hidden = true;
      secretHeading.hidden = true;
      show("Secret clipped. Close this tab.");
    }, CLIP_SECONDS * 1000);
  } catch (error) {
    button.disabled = false;
    show(error instanceof Error ? error.message : "Reveal failed.", true);
  }
});