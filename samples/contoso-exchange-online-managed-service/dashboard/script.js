const controlDescriptions = {
  acceptedDomainAuthoritative: ["Accepted domain", "Cloud-only recipient boundary is authoritative."],
  proofpointInboundEnabled: ["Proofpoint inbound", "Constrained Partner connector is enabled."],
  proofpointInboundTls: ["Inbound TLS", "Proofpoint delivery requires TLS."],
  enhancedFilteringEnabled: ["Enhanced filtering", "Microsoft sees the original internet sender."],
  proofpointOutboundEnabled: ["Proofpoint outbound", "Outbound internet mail uses the approved gateway."],
  smtpAuthDisabled: ["SMTP AUTH", "Legacy authenticated submission is disabled globally."],
  automaticForwardingOff: ["External forwarding", "Automatic forwarding is blocked by default."],
  mdoFilesProtectionEnabled: ["Files protection", "SharePoint, OneDrive, and Teams scanning is enabled."],
  safeDocumentsBypassBlocked: ["Safe Documents", "Users cannot bypass a malicious verdict."],
  dkimEnabledAndValid: ["DKIM", "The sending domain signs with a valid configuration."],
  standardPresetEnabled: ["Standard preset", "Standard EOP and MDO rules are enabled."],
  strictPresetEnabled: ["Strict preset", "Priority-user EOP and MDO rules are enabled."],
  noSclMinusOneBypassRules: ["Filtering bypass", "No SCL -1 transport rules are present."]
};

const baselineChecks = Object.fromEntries(Object.keys(controlDescriptions).map((key) => [key, null]));
const list = document.querySelector("#control-list");
const template = document.querySelector("#control-template");
let checks = baselineChecks;

function render(filter = "all") {
  list.replaceChildren();
  let passing = 0;
  let failing = 0;

  Object.entries(checks).forEach(([key, value]) => {
    const state = value === true ? "pass" : value === false ? "fail" : "neutral";
    if (state === "pass") passing += 1;
    if (state === "fail") failing += 1;
    if (filter !== "all" && state !== filter) return;

    const row = template.content.firstElementChild.cloneNode(true);
    const description = controlDescriptions[key] || [key, "Collected tenant control."];
    row.classList.add(state);
    row.querySelector("h3").textContent = description[0];
    row.querySelector("p").textContent = description[1];
    const badge = row.querySelector(".status");
    badge.classList.add(state);
    badge.textContent = state === "neutral" ? "NOT LOADED" : state.toUpperCase();
    list.append(row);
  });

  document.querySelector("#pass-count").textContent = passing;
  document.querySelector("#fail-count").textContent = failing;
  document.querySelector("#coverage-count").textContent = Object.keys(checks).length;
}

document.querySelector("#evidence-file").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  try {
    const payload = JSON.parse(await file.text());
    if (!payload.checks || typeof payload.checks !== "object") throw new Error("Missing checks object");
    checks = payload.checks;
    const collected = payload.evidence?.collectedAtUtc || "unknown time";
    document.querySelector("#collection-status").textContent = `Live evidence collected ${collected}.`;
    render();
  } catch (error) {
    document.querySelector("#collection-status").textContent = `Evidence file rejected: ${error.message}`;
  }
});

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-filter]").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    render(button.dataset.filter);
  });
});

render();