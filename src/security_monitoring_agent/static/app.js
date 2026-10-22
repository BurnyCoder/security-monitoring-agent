// Global: dashboard orchestration. Local: clearly named phases load data, render views, and follow runs; https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules.
import { request, streamRun } from "./api.js"; // Keep transport separate from interface state.
import { el, date, panel, empty } from "./ui.js"; // Share safe text rendering and date formatting.
import { overview, findingsView, newsList, inventoryView, historyView, showFinding } from "./views.js"; // Delegate evidence presentation to modular views.
import { settingsView } from "./settings.js"; // Isolate configuration form logic.
import { chatView } from "./chat.js"; // Isolate persisted conversation logic.

const pages = { overview: ["Overview", "Security overview", "Fresh intelligence. Local evidence. A clear next step."], findings: ["Device findings", "Device findings", "Understand which vulnerabilities apply to your installed software."], intelligence: ["Threat intelligence", "Threat intelligence", "New vulnerabilities, exploitation reports, and the sources behind them."], inventory: ["Device inventory", "Device inventory", "Inspect exactly what was observed across Windows, WSL, and your projects."], history: ["Scan history", "Investigation history", "Trace each investigation from its first command to its final assessment."], chat: ["Ask an agent", "Ask your security agent", "Go deeper on the evidence, a proposed fix, or a question about your device."], settings: ["Settings", "Workspace settings", "Your agent, your schedule, and the scope of your investigations."] }; // Keep route copy in one place.
const humanEventKinds = new Set(["phase", "progress", "agent_text", "agent_result", "state", "error", "done", "source"]); // Show readable investigation milestones by default; raw process streams remain available separately.
const state = { status: null, settings: null, stream: null, streamId: null, logRunId: null, events: [], humanEvents: [], seen: new Set(), route: "overview", version: 0, chatId: null, findingId: null, busy: false, statusBusy: false, initialized: false, paintTimer: null }; // Keep only necessary view and live-run state.

function showError(error) {
  // Global: visible failures. Local: never insert exception text as HTML.
  document.querySelector("#error-text").textContent = error.message || String(error); document.querySelector("#error-banner").hidden = false; // Expose actionable server errors.
}

function syncSettings(settings) {
  // Global: one persisted configuration. Local: update quick controls after initial load or an explicit settings save.
  state.settings = settings; document.querySelector("#scan-provider").value = settings.provider; document.querySelector("#scan-model").value = settings.model; document.querySelector("#scan-window").value = String(settings.news_days); // Leave model IDs unrestricted.
}

function updateStatus(status) {
  // Global: shared run lifecycle. Local: render summary controls without rebuilding forms or interrupting typing.
  state.status = status; const active = status.active_run; // Use server state as the authoritative worker status.
  document.querySelector("#connection").replaceChildren(el("span", { class: "device-dot" }), "Local workspace"); // Successful status requests prove the app connection.
  document.querySelector("#run-scan").disabled = Boolean((active && active.kind !== "chat") || state.busy); document.querySelector("#cancel-scan").hidden = !active; document.querySelector("#cancel-scan").textContent = active?.kind === "chat" ? "Stop agent" : "Stop scan"; // Scan and chat locks are independent, so a conversation never prevents a new scan.
  document.querySelector("#scan-state").textContent = active ? (active.kind === "chat" ? "Agent is working" : "Investigation in progress") : status.last_successful ? `Last scan ${date(status.last_successful.finished_at)}` : "Ready for your first scan"; // Never label an unscanned device protected.
  document.querySelector("#nav-findings").textContent = Number(status.counts?.affected || 0) + Number(status.counts?.potentially_affected || 0); // Count actionable installations in navigation.
  document.querySelector("#schedule-summary").textContent = !status.settings.auto_scan ? "Automatic scans paused" : status.next_scan_at ? `Next scan ${date(status.next_scan_at)}` : `Every ${status.settings.interval_minutes} minutes`; // Show the actual configured cadence.
  document.querySelector("#last-updated").textContent = `Workspace synced ${new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`; // Distinguish UI sync from evidence collection time.
  const indicator = document.querySelector("#activity-indicator"); if (indicator) { indicator.className = active ? "live-pill" : "quiet-pill"; indicator.textContent = active ? "LIVE" : "READY"; } // Update overview activity state in place.
  if (active) followRun(active); else if (state.stream) { state.stream.close(); state.stream = null; state.streamId = null; } // End the client stream once the server reports completion.
}

function paintActivity() {
  // Global: live readable investigation trace. Local: the visible tail is bounded while the downloadable log remains complete.
  const log = document.querySelector("#activity-log"); if (!log) return; // Other routes do not own an activity pane.
  const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80; // Preserve a user's position while they inspect earlier events.
  const visible = document.querySelector("#activity-raw")?.checked ? state.events : state.humanEvents; // Raw stdout, stderr, and prompts are opt-in; both tails contain complete events.
  if (!visible.length) log.replaceChildren(el("div", { class: "activity-empty" }, el("span", { class: "activity-empty-icon", "aria-hidden": "true" }, "⌁"), el("strong", {}, state.status?.active_run ? "Waiting for the next update" : "A live view of your investigation"), el("p", {}, "Inventory checks, web research, and agent updates appear here. Enable Raw events or download the full log for process output."))); // Explain how to inspect hidden transport events without presenting them as findings.
  else log.replaceChildren(...visible.slice(-160).map((event) => el("div", { class: `activity-event${event.kind === "error" ? " event-error" : ""}` }, el("div", { class: "activity-event-meta" }, el("span", {}, event.kind || "activity"), el("time", {}, event.created_at ? new Date(event.created_at).toLocaleTimeString(undefined, { hour12: false }) : "")), el("pre", {}, event.text || "")))); // Show complete event text inside the selected visible tail.
  if (nearBottom) log.scrollTop = log.scrollHeight; // Follow live output only while the reader stays near the end.
  const download = document.querySelector("#activity-download"); if (download) { download.hidden = !state.logRunId; if (state.logRunId) { download.href = `/api/runs/${encodeURIComponent(state.logRunId)}/log`; download.setAttribute("download", ""); } } // Full prompt and output logs remain one click away.
}

function followRun(run) {
  // Global: one stream per active run. Local: deduplicate replayed IDs after native EventSource reconnects.
  if (state.streamId === run.id) return; // Polling status must not reopen the same stream.
  state.stream?.close(); state.streamId = run.id; // Close a previous stream before switching the cursor.
  if (state.logRunId !== run.id) { state.logRunId = run.id; state.events = []; state.humanEvents = []; state.seen.clear(); } // Give each run its own raw and readable log tails.
  state.stream = streamRun(run.id, (event) => { // All event types are rendered as progress text.
    if (event.id !== undefined && state.seen.has(String(event.id))) return; // Avoid duplicate log lines after reconnect.
    if (event.id !== undefined) state.seen.add(String(event.id)); state.events.push(event); // Track the server event identity.
    if (state.events.length > 200) state.events.shift(); // Bound browser memory without truncating persisted logs.
    if (humanEventKinds.has(event.kind)) { state.humanEvents.push(event); if (state.humanEvents.length > 160) state.humanEvents.shift(); } // Frequent raw diagnostics cannot evict readable milestones from their independent tail.
    if (state.seen.size > 2000) state.seen = new Set(state.events.map((item) => String(item.id))); // Bound reconnect bookkeeping during long sessions.
    if (!state.paintTimer) state.paintTimer = setTimeout(() => { state.paintTimer = null; paintActivity(); }, 120); // Batch rapid streaming events without delaying persisted full logs.
  });
}

async function scan() {
  // Global: dispatch a real manual scan. Local: quick controls are per-run overrides, not implicit settings writes.
  if (state.busy || (state.status?.active_run && state.status.active_run.kind !== "chat")) return; state.busy = true; document.querySelector("#run-scan").disabled = true; // Prevent duplicate scans while allowing independent conversation work.
  try { const model = document.querySelector("#scan-model").value.trim(); if (!model) throw new Error("Enter a model identifier before starting a scan."); const run = await request("/runs", { method: "POST", body: { provider: document.querySelector("#scan-provider").value, model, news_days: Number(document.querySelector("#scan-window").value) } }); followRun(run); await refreshStatus(); if (state.route !== "overview") location.hash = "overview"; else await renderRoute(); } // Show progress immediately after server acceptance.
  catch (error) { showError(error); } // Preserve controls and report validation/provider startup errors.
  finally { state.busy = false; document.querySelector("#run-scan").disabled = Boolean(state.status?.active_run && state.status.active_run.kind !== "chat"); } // Restore the action based on scan ownership only.
}

function closeDrawer() {
  // Global: modal lifecycle. Local: hide the overlay and restore normal document scrolling.
  document.querySelector("#detail-drawer").hidden = true; document.querySelector("#drawer-backdrop").hidden = true; document.body.classList.remove("drawer-open"); // No finding data or backend state changes.
}

const actions = { scan, error: showError, details: (finding) => showFinding(finding, actions), ask: (finding) => { closeDrawer(); state.chatId = null; state.findingId = finding.id; if (state.route === "chat") renderRoute(); else location.hash = "chat"; }, saved: (settings) => { syncSettings(settings); refreshStatus(); }, selected: (id) => { state.chatId = id; if (id) state.findingId = null; }, started: (run) => { if (!state.status?.active_run) followRun(run); refreshStatus(); } }; // Explicit callbacks connect views to application phases.

async function renderRoute() {
  // Global: independently load each workspace view. Local: version guards prevent slow requests replacing a newer route.
  const route = location.hash.slice(1).split("?")[0] || "overview"; state.route = pages[route] ? route : "overview"; const version = ++state.version; const page = pages[state.route]; // Resolve only known local routes.
  document.querySelector("#breadcrumb").textContent = page[0]; document.querySelector("#page-title").textContent = page[1]; document.querySelector("#page-description").textContent = page[2]; // Keep shared chrome aligned with the active view.
  document.querySelectorAll("[data-view]").forEach((link) => { link.classList.toggle("active", link.dataset.view === state.route); if (link.dataset.view === state.route) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); }); // Expose navigation state accessibly.
  const target = document.querySelector("#view"); target.classList.add("is-loading"); // Keep existing content while the next route loads.
  try { // Fetch only the collections needed by the chosen route.
    let content; // One DOM result is mounted atomically after all dependent data arrives.
    if (state.route === "overview") { const [findings, advisories, inventory] = await Promise.all([request("/findings"), request("/advisories"), request("/inventory")]); content = overview({ status: state.status, findings, advisories, inventory }, actions); } // Parallelize independent evidence reads.
    else if (state.route === "findings") content = findingsView(await request("/findings"), actions); // Triage the complete findings list.
    else if (state.route === "intelligence") { const advisories = await request("/advisories"); content = panel("Tracked intelligence", `${advisories.length} advisories · News recency is configured per scan`, newsList(advisories)); } // Keep intelligence distinct from exposure.
    else if (state.route === "inventory") content = inventoryView(await request("/inventory")); // Coverage and raw inventory share one snapshot.
    else if (state.route === "history") content = historyView(await request("/runs"), actions); // Include failed investigations and full logs.
    else if (state.route === "settings") content = settingsView(await request("/settings"), actions); // Use persisted values rather than stale quick-control overrides.
    else if (state.route === "chat") content = await chatView(state.settings, actions, state.chatId, state.findingId); // Preserve explicit conversation identity across navigation.
    if (version !== state.version) return; target.replaceChildren(content); document.querySelector("#activity-raw")?.addEventListener("change", paintActivity); paintActivity(); // Ignore outdated route responses and bind the newly mounted raw-event toggle.
  } catch (error) { if (version === state.version) { target.replaceChildren(empty("This view could not be loaded", error.message)); showError(error); } } // Failure stays recoverable through navigation or refresh.
  finally { if (version === state.version) target.classList.remove("is-loading"); } // Do not alter a newer route's loading state.
}

async function refreshStatus() {
  // Global: recover from missed SSE lifecycle events. Local: lightweight status polling also updates scheduled runs.
  if (state.statusBusy) return; state.statusBusy = true; // Avoid overlapping polls when a request is slow.
  try { const previous = state.status?.active_run?.id; const status = await request("/status"); updateStatus(status); if (!state.initialized) { syncSettings(status.settings); state.initialized = true; await renderRoute(); } else if (previous && previous !== status.active_run?.id) { if (state.route === "chat") await document.querySelector(".chat-layout")?.refreshConversation?.(); else if (state.route !== "settings") await renderRoute(); } } // Refresh results only when a run completes, protecting drafts and filters otherwise.
  catch (error) { document.querySelector("#connection").replaceChildren(el("span", { class: "device-dot offline" }), "Disconnected"); if (!state.initialized) showError(error); } // Connectivity loss is visible without repeated error banners.
  finally { state.statusBusy = false; } // Permit later reconnect attempts.
}

function bindControls() {
  // Global: one-time shell event wiring. Local: native event listeners keep behavior separate from HTML.
  document.querySelector("#run-scan").addEventListener("click", scan); // Dispatch the selected provider and model.
  document.querySelector("#scan-provider").addEventListener("change", (event) => { document.querySelector("#scan-model").value = event.target.value === "claude" ? "haiku" : "gpt-6-luna"; }); // Suggest each tested lightweight model.
  document.querySelector("#cancel-scan").addEventListener("click", async () => { const run = state.status?.active_run; if (!run) return; const control = document.querySelector("#cancel-scan"); control.disabled = true; try { await request(`/runs/${encodeURIComponent(run.id)}/cancel`, { method: "POST" }); await refreshStatus(); } catch (error) { showError(error); } finally { control.disabled = false; } }); // Cancel only the explicitly displayed active run.
  document.querySelector("#dismiss-error").addEventListener("click", () => { document.querySelector("#error-banner").hidden = true; }); // Dismiss presentation without hiding persisted failure records.
  document.querySelector("#close-drawer").addEventListener("click", closeDrawer); document.querySelector("#drawer-backdrop").addEventListener("click", closeDrawer); // Provide keyboard and pointer close controls.
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); if (event.key === "Tab" && !document.querySelector("#detail-drawer").hidden) { const controls = [...document.querySelector("#detail-drawer").querySelectorAll("button,a[href],input,select,textarea")]; const first = controls[0]; const last = controls.at(-1); if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); } } }); // Keep focus inside the modal until it closes.
  window.addEventListener("hashchange", () => { closeDrawer(); if (state.initialized) renderRoute(); }); // Route changes preserve scan and chat execution.
  window.addEventListener("beforeunload", () => state.stream?.close()); // Close only the browser subscription, not the background process.
}

bindControls(); await refreshStatus(); setInterval(refreshStatus, 5000); // Bootstrap the workspace and follow server-owned schedules.
