// Global: persisted local configuration. Local: native form controls map directly to Settings; https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement.
import { request } from "./api.js"; // Use shared transport and error handling.
import { el, button, panel, labeled, select } from "./ui.js"; // Reuse escaped rendering and consistent controls.

export function settingsView(settings, actions) {
  // Global: make automation and scope understandable. Local: edit one complete validated Settings object.
  const provider = select([["codex", "Codex"], ["claude", "Claude Code"]], settings.provider); // Select one provider per scan.
  const model = el("input", { value: settings.model, required: "", list: "model-suggestions", autocomplete: "off" }); // Keep arbitrary provider model IDs available.
  provider.addEventListener("change", () => { model.value = provider.value === "claude" ? "haiku" : "gpt-6-luna"; }); // Start each provider with its tested default.
  const interval = el("input", { type: "number", min: 1, max: 10080, value: settings.interval_minutes, required: "" }); // Mirror backend minute constraints.
  const timeout = el("input", { type: "number", min: 30, max: 14400, value: settings.timeout_seconds, required: "" }); // Let the user bound each invocation.
  const auto = el("input", { type: "checkbox", checked: settings.auto_scan }); // Preserve the stored scheduling preference.
  const news = select([[1, "Last 24 hours"], [7, "Last 7 days"], [30, "Last 30 days"]], settings.news_days); // News windows do not filter existing exposure.
  const schedule = select([["app", "While the app is running"], ["login", "Start the dashboard at Windows login"], ["task", "Windows scheduled scans"]], settings.schedule_mode); // Expose explicit background modes.
  const paths = Object.fromEntries(["codex_path", "claude_path", "osv_path"].map((key) => [key, el("input", { value: settings[key], required: "", spellcheck: "false" })])); // Advanced executable paths remain editable.
  const roots = el("div", { class: "project-roots" }); // Each row represents one explicit project boundary.
  const addRoot = (root = { kind: "windows", path: "", distribution: "" }) => { // Global: selected dependency scope only. Local: add an editable row without browsing unrelated folders.
    const kind = select([["windows", "Windows"], ["wsl", "WSL"]], root.kind, { "aria-label": "Project platform", class: "root-kind" }); // Identify how the backend addresses the path.
    const path = el("input", { value: root.path, placeholder: "Absolute project path", required: "", "aria-label": "Project path", class: "root-path" }); // Require an explicit path.
    const distribution = el("input", { value: root.distribution, placeholder: "WSL distribution", "aria-label": "WSL distribution", class: "root-distribution", hidden: kind.value !== "wsl" }); // Distribution is meaningful only for WSL.
    const row = el("div", { class: "project-root" }, kind, path, distribution, button("×", () => row.remove(), "icon-button remove-root")); // Removing the row changes scope only on save.
    row.lastChild.setAttribute("aria-label", "Remove project folder"); // Explain the compact icon to assistive technology.
    kind.addEventListener("change", () => { distribution.hidden = kind.value !== "wsl"; distribution.required = kind.value === "wsl"; }); // Keep validation aligned with platform.
    distribution.required = kind.value === "wsl"; roots.append(row); // Initialize validation for existing WSL roots.
  };
  settings.project_roots.forEach(addRoot); // Render only configured folders.
  const save = el("button", { type: "submit", class: "button button-primary" }, "Save settings"); // One explicit save applies the entire configuration.
  const feedback = el("span", { class: "save-feedback", role: "status" }); // Report whether validation and persistence succeeded.
  const diagnostics = el("div", { class: "diagnostics-content muted" }, "Check installed executable versions. Inspect provider login status in its CLI."); // Version probes do not establish authentication or model access.
  const check = button("Check connections", async () => { // Global: actionable setup feedback. Local: inspect backend diagnostics without starting a scan.
    check.disabled = true; diagnostics.textContent = "Checking local tools…"; // Prevent redundant diagnostic requests.
    try { const data = await request("/diagnostics"); diagnostics.replaceChildren(el("pre", { class: "diagnostics-json" }, JSON.stringify(data, null, 2))); } // Preserve complete diagnostics instead of guessing their shape.
    catch (error) { diagnostics.textContent = error.message; actions.error(error); } // Keep errors visible locally and globally.
    finally { check.disabled = false; } // Always restore the interaction.
  });
  const agentFields = el("div", { class: "form-grid" }, labeled("Default provider", provider), labeled("Model", model, "Any model identifier supported by the selected provider."), labeled("News window", news, "Older vulnerabilities remain in device findings."), labeled("Agent timeout (seconds)", timeout)); // Keep agent preferences as one independently readable form section.
  const automaticToggle = el("label", { class: "toggle-field full-width" }, auto, el("span", {}, el("strong", {}, "Automatic scanning"), el("small", {}, "Repeat investigations at your configured interval."))); // Associate the checkbox with its visible label.
  const scheduleNote = el("p", { class: "field-note full-width" }, "While-app mode pauses when Sentinel closes. Login and scheduled-task modes use your Windows account and existing CLI sign-ins."); // Explain schedule ownership beside the setting.
  const scheduleFields = el("div", { class: "form-grid" }, automaticToggle, labeled("Interval (minutes)", interval), labeled("Run mode", schedule), scheduleNote); // Separate scheduling controls from presentation nesting.
  const projectFields = el("div", { class: "form-section" }, roots, button("+ Add project folder", () => addRoot(), "button button-secondary")); // Reuse explicit scope rows and their add action.
  const mainColumn = el("div", { class: "stack" }, // Global: primary settings column. Local: compose three complete panels with balanced argument boundaries.
    panel("Agent & investigation", "Use your existing Codex or Claude Code sign-in", agentFields), // Provider and model preferences.
    panel("Scan schedule", "Choose when the next investigation starts", scheduleFields), // Automatic schedule preferences.
    panel("Project dependency folders", "Windows and WSL inventory is collected automatically. Add explicit project folders for dependency checks.", projectFields)); // Explicit project scope.
  const advancedFields = el("details", { class: "advanced-settings" }, el("summary", {}, "Advanced executable paths"), labeled("Codex CLI", paths.codex_path), labeled("Claude Code CLI", paths.claude_path), labeled("OSV Scanner", paths.osv_path)); // Advanced paths share one collapsible group.
  const executionFields = el("div", { class: "form-section" }, el("p", { class: "settings-note" }, "Web search and local inspection are enabled. Remediation appears as instructions and copyable commands."), advancedFields); // Show the configured execution behavior without adding approval controls.
  const sideColumn = el("div", { class: "stack" }, // Global: supporting setup column. Local: diagnostics do not change persisted preferences.
    panel("Execution settings", "Agents run with the requested unrestricted CLI permissions", executionFields), // Summarize unrestricted CLI behavior.
    panel("Local connections", "Verify the tools available to this application", el("div", { class: "form-section" }, check, diagnostics))); // Keep diagnostics together with their trigger.
  const form = el("form", { class: "settings-layout" }, mainColumn, sideColumn, el("div", { class: "settings-save" }, feedback, save)); // One shallow form composition avoids ambiguous nested closing parentheses.
  form.addEventListener("submit", async (event) => { // Global: validate and save a coherent configuration. Local: browser validation precedes backend validation.
    event.preventDefault(); save.disabled = true; feedback.textContent = "Saving…"; // Avoid duplicate writes while persistence is pending.
    const project_roots = [...roots.children].map((row) => ({ kind: row.querySelector(".root-kind").value, path: row.querySelector(".root-path").value.trim(), distribution: row.querySelector(".root-kind").value === "wsl" ? row.querySelector(".root-distribution").value.trim() : "" })); // Convert rows directly to ProjectRoot objects.
    const payload = { ...settings, provider: provider.value, model: model.value.trim(), interval_minutes: Number(interval.value), timeout_seconds: Number(timeout.value), auto_scan: auto.checked, news_days: Number(news.value), schedule_mode: schedule.value, project_roots, ...Object.fromEntries(Object.entries(paths).map(([key, field]) => [key, field.value.trim()])) }; // Preserve complete typed settings and explicit scopes.
    try { const saved = await request("/settings", { method: "PATCH", body: payload }); feedback.textContent = "Settings saved"; actions.saved(saved); } // Synchronize global controls only after backend success.
    catch (error) { feedback.textContent = "Could not save settings"; actions.error(error); } // Preserve unsaved inputs for correction.
    finally { save.disabled = false; } // Restore saving after either result.
  });
  return form; // The orchestrator mounts this form for the settings route.
}
