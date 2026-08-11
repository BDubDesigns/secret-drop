import sodium from "/static/libsodium-wrappers.mjs";

const landing = document.querySelector("#landing");
const delivery = document.querySelector("#delivery");
const handoffMessage = document.querySelector("#handoff-message");
const input = document.querySelector("#input");
const button = document.querySelector("#send");
const status = document.querySelector("#status");
const copyAgentButton = document.querySelector("#copy-agent-url");
const agentUrl = document.querySelector("#agent-url");
const agentCopyStatus = document.querySelector("#agent-copy-status");

function show(message, error = false) {
  status.hidden = false;
  status.style.display = "block";
  status.textContent = message;
  status.dataset.error = error ? "true" : "false";
}

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

const link = receiverLink();
if (link.state === "valid") {
  landing.hidden = true;
  delivery.hidden = false;
  button.disabled = false;
} else {
  landing.hidden = false;
  delivery.hidden = true;
  button.disabled = true;
  if (link.state === "invalid") {
    handoffMessage.textContent = "Incomplete or invalid handoff link. Ask your agent for a fresh link.";
    handoffMessage.dataset.error = "true";
  }
}

copyAgentButton.addEventListener("click", async () => {
  const value = agentUrl.textContent;
  try {
    await navigator.clipboard.writeText(value);
    agentCopyStatus.hidden = false;
    agentCopyStatus.textContent = "Copied. This is a public guide URL, not a secret.";
  } catch {
    agentCopyStatus.hidden = false;
    agentCopyStatus.textContent = "Copy was blocked by the browser. Select the guide URL manually.";
  }
});

button.addEventListener("click", async () => {
  if (link.state !== "valid") return;
  const secret = input.value;
  if (!secret) {
    show("Paste a secret first.", true);
    return;
  }
  button.disabled = true;
  show("Encrypting and delivering…");
  try {
    await sodium.ready;
    const publicKey = sodium.from_base64(link.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING);
    const encrypted = sodium.crypto_box_seal(sodium.from_string(secret), publicKey);
    const payload = sodium.to_base64(encrypted, sodium.base64_variants.URLSAFE_NO_PADDING);
    const response = await fetch(`/api/drops/${link.id}/payload`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      body: JSON.stringify({ v: 1, payload }),
    });
    if (!response.ok) {
      if (response.status === 404) throw new Error("This handoff has expired or was already used.");
      if (response.status === 429) throw new Error("Too many attempts. Wait a minute and try again.");
      throw new Error("The relay rejected this handoff.");
    }
    input.value = "";
    show("Delivered. You can close this tab.");
  } catch (error) {
    button.disabled = false;
    show(error instanceof Error ? error.message : "Delivery failed.", true);
  }
});
