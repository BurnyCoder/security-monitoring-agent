// Global: evidence-driven dashboard views. Local: compose escaped DOM nodes from API contracts; https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent.
import { el, button, badge, date, empty, panel, sourceLinks, select, filterSelect, copy } from "./ui.js"; // Share rendering primitives across views.

const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }; // Consistently prioritize source-backed severity.

function findingScope(finding) {
  // Global: separate OS installations from recorded project dependencies. Local: classify explicit asset kinds before platform labels.
  const kind = finding.asset?.kind || ""; // Missing assets stay unclassified rather than inferred from an advisory.
  if (kind === "project_dependency") return "project"; // A project dependency remains a project finding on Windows and WSL alike.
  if (kind.startsWith("wsl_") || /^WSL\b/i.test(finding.asset?.platform || "")) return "wsl"; // Named distributions belong to the WSL scope.
  if (kind.startsWith("windows_") || /^Windows\b/i.test(finding.asset?.platform || "")) return "windows"; // Native OS/application assets belong to Windows.
  return "unknown"; // Unknown scope remains visible through the all/unclassified choices.
}

function findingSourceHosts(finding) {
  // Global: filter by actual cited provenance. Local: derive source domains from both assessment and advisory citations; https://developer.mozilla.org/en-US/docs/Web/API/URL/hostname.
  const hosts = new Set(); // One source domain appears once even when several URLs support a finding.
  for (const source of [...(finding.sources || []), ...(finding.advisory?.sources || [])]) { // Include both applicability and general vulnerability evidence.
    try { const url = new URL(source.url); if (url.protocol === "http:" || url.protocol === "https:") hosts.add(url.hostname.replace(/^www\./, "")); } catch { /* A malformed source cannot break the triage view. */ }
  }
  return [...hosts]; // Stable domain values are suitable for native select options.
}

export function metrics(status) {
  // Global: honest at-a-glance counts. Local: missing counts become zero, without implying a clean device.
  const counts = status.counts || {}; // The backend owns finding aggregation.
  const cards = [["Affected installations", counts.affected || 0, "Requires attention", "affected", "◇"], ["Potentially affected", counts.potentially_affected || 0, "Needs verification", "potentially_affected", "△"], ["Unknown applicability", counts.unknown || 0, "More evidence needed", "unknown", "?"], ["Tracked advisories", counts.advisories || 0, "Intelligence collected", "intelligence", "◎"]]; // Distinguish exposure from news volume.
  return el("div", { class: "metrics" }, cards.map(([label, count, detail, type, icon]) => el("div", { class: `metric metric-${type}` }, el("div", { class: "metric-top" }, el("span", {}, label), el("span", { class: "metric-icon", "aria-hidden": "true" }, icon)), el("strong", { class: "metric-number" }, count), el("span", { class: "metric-detail" }, el("span", { class: "metric-dot" }), detail)))); // Keep counts directly readable.
}

export function findingTable(findings, actions, compact = false) {
  // Global: installation-specific findings. Local: table rows lead to evidence and copyable remediation.
  if (!findings.length) return empty("No findings to show", "Run a scan to compare your Windows and WSL inventory with current vulnerability intelligence.", button("Run a scan", actions.scan, "button button-primary")); // Avoid declaring unscanned devices safe.
  const sorted = [...findings].sort((a, b) => (riskOrder[a.advisory?.severity] ?? 4) - (riskOrder[b.advisory?.severity] ?? 4)); // Keep the original API array immutable.
  const visible = compact ? sorted.slice(0, 6) : sorted; // The overview deliberately shows a short, linked preview.
  return el("div", { class: "table-scroll" }, el("table", { class: "findings-table" }, el("thead", {}, el("tr", {}, ["Severity", "Vulnerability / installation", "Assessment", "Checked", ""].map((label) => el("th", { scope: "col" }, label)))), el("tbody", {}, visible.map((finding) => el("tr", {}, el("td", {}, badge(finding.advisory?.severity || "unknown")), el("td", {}, button(finding.advisory?.id || finding.advisory_id, () => actions.details(finding), "text-button finding-id"), el("div", { class: "finding-title" }, finding.advisory?.title || "Advisory details unavailable"), el("div", { class: "muted table-meta" }, `${finding.asset?.name || finding.asset_id} ${finding.asset?.version || ""}`, el("span", { class: "meta-dot" }, "·"), finding.asset?.platform || "Unknown platform")), el("td", {}, badge(finding.status), finding.stale ? el("div", { class: "stale-label" }, "Earlier inventory") : null), el("td", { class: "muted nowrap" }, date(finding.checked_at)), el("td", {}, button("↗", () => actions.details(finding), "icon-button row-open"))))))); // Never inject vulnerability content as markup.
}

export function overview(data, actions) {
  // Global: primary dashboard. Local: combine exposure, inventory scope, and live progress without duplicating data.
  const coverage = data.inventory?.coverage || []; // Coverage comes from the latest collected inventory.
  const covered = coverage.filter((item) => item.status === "ok").length; // Count fully completed collectors only.
  const active = data.status.active_run; // The API decides whether a scan or chat is running.
  const summary = data.status.last_successful?.summary; // A successful run summary is evidence, not a marketing claim.
  const lastScan = el("div", { class: "scan-summary" }, el("span", { class: "summary-icon", "aria-hidden": "true" }, active ? "◌" : "◎"), el("div", {}, el("strong", {}, active ? "An investigation is in progress" : data.status.last_successful ? "Latest investigation" : "Your first scan starts here"), el("p", {}, active ? `${active.provider} · ${active.model} · Started ${date(active.started_at)}` : summary || "Sentinel checks installed software, searches fresh sources, and explains which findings apply to this device.")), el("a", { href: "#history", class: "text-link" }, "View history ↗")); // Keep the introductory state useful before any run.
  const activity = panel("Live activity", "Follow your agent's investigation", el("div", { id: "activity-log", class: "activity-log", role: "log", "aria-live": "polite" }), el("span", { id: "activity-indicator", class: active ? "live-pill" : "quiet-pill" }, active ? "LIVE" : "READY")); // App orchestration fills this log from SSE.
  activity.append(el("div", { class: "panel-footer activity-footer" }, el("a", { id: "activity-download", class: "text-link", hidden: true }, "Download full log ↗"), el("label", { class: "activity-toggle" }, el("input", { id: "activity-raw", type: "checkbox" }), "Raw events"))); // Human-readable activity is the default; complete logs and raw event inspection remain accessible.
  const coverageCard = panel("Monitoring coverage", "What this device scan can see", coverage.length ? el("div", { class: "coverage-mini" }, coverage.slice(0, 5).map((item) => el("div", {}, el("span", {}, item.component), badge(item.status))), el("div", { class: "coverage-total" }, `${covered} of ${coverage.length} collectors fully covered`, el("a", { href: "#inventory" }, "Inspect coverage ↗"))) : el("div", { class: "quiet-empty" }, "Inventory is collected when the first scan starts.", el("a", { href: "#settings" }, "Choose project folders ↗"))); // Failed collectors remain discoverable.
  return el("div", {}, metrics(data.status), lastScan, el("div", { class: "overview-grid" }, el("div", { class: "main-column" }, panel("Device findings", "Vulnerabilities assessed against your installed software", findingTable(data.findings, actions, true), el("a", { href: "#findings", class: "text-link" }, "View all ↗")), panel("Intelligence watch", "Recent advisories and exploitation reports", newsList(data.advisories.slice(0, 3), true), el("a", { href: "#intelligence", class: "text-link" }, "Explore ↗"))), el("div", { class: "side-column" }, activity, coverageCard))); // Establish one primary findings column and one activity column.
}

export function findingsView(findings, actions) {
  // Global: focused triage workflow. Local: client filters operate on the complete server response.
  const search = el("input", { type: "search", placeholder: "Search CVE, product, or platform…", "aria-label": "Search findings", class: "search-input" }); // Native search supports quick clearing.
  const records = findings.map((finding) => ({ finding, scope: findingScope(finding), hosts: findingSourceHosts(finding), text: [finding.advisory_id, finding.advisory?.title, finding.asset?.name, finding.asset?.platform].join(" ").toLowerCase() })); // Compute reusable filter metadata once per loaded response.
  const assessment = filterSelect("All assessments", [["affected", "Affected"], ["potentially_affected", "Potentially affected"], ["unknown", "Unknown"], ["not_affected", "Not affected"]]); // Expose definitive and uncertain states separately.
  const severity = filterSelect("All severities", Object.keys(riskOrder).map((key) => [key, key[0].toUpperCase() + key.slice(1)])); // Match the shared severity vocabulary.
  const exploitation = filterSelect("All exploitation evidence", [["known_exploited", "Known exploited"], ["public_poc", "Public proof of concept"], ["unverified_report", "Unverified report"], ["none_known", "No known exploit"]]); // Distinguish reported exploitation from published PoCs and absent reports.
  const scope = filterSelect("All installation scopes", [["windows", "Windows"], ["wsl", "WSL"], ["project", "Project dependencies"], ["unknown", "Unclassified"]]); // Use observed installation identity, not product-name guesses.
  const sourceHosts = [...new Set(records.flatMap((record) => record.hosts))].sort(); // Build source choices only from actual citations.
  const source = filterSelect("All cited sources", [...sourceHosts.map((host) => [host, host]), ["uncited", "No cited source"]]); // Keep uncited assessments explicitly discoverable.
  const content = el("div"); // Replace only the filtered table, preserving input focus.
  const render = () => { // Global: predictable filters. Local: include source identity and installed product fields.
    const term = search.value.trim().toLowerCase(); // Normalize user text without changing source text.
    const filtered = records.filter((record) => (!term || record.text.includes(term)) && (assessment.value === "all" || record.finding.status === assessment.value) && (severity.value === "all" || record.finding.advisory?.severity === severity.value) && (exploitation.value === "all" || record.finding.advisory?.exploitation === exploitation.value) && (scope.value === "all" || record.scope === scope.value) && (source.value === "all" || (source.value === "uncited" ? !record.hosts.length : record.hosts.includes(source.value)))).map((record) => record.finding); // Combine every selected constraint without changing the underlying evidence.
    content.replaceChildren(filtered.length ? findingTable(filtered, actions) : empty(findings.length ? "No matching findings" : "No findings yet", findings.length ? "Adjust the search, assessment, severity, exploitation, installation scope, or source filters." : "Run a scan to collect local evidence and assess vulnerabilities.")); // Distinguish no results from an unscanned device.
  };
  [search, assessment, severity, exploitation, scope, source].forEach((control) => control.addEventListener("input", render)); // Native input handles keyboard and pointer changes across every filter.
  render(); // Populate the initial unfiltered view.
  return panel("All device findings", `${findings.length} installation assessments`, el("div", {}, el("div", { class: "filter-toolbar findings-filters" }, search, assessment, severity, exploitation, scope, source), content)); // Keep all filter controls adjacent to their results.
}

export function newsList(advisories, compact = false) {
  // Global: distinguish intelligence from applicability. Local: news alone never labels this device affected.
  if (!advisories.length) return empty("Intelligence will appear here", "Your selected agent searches the web during each scan. Advisories include source links and exploitation evidence."); // No fabricated sample threats.
  return el("div", { class: "news-list" }, advisories.map((advisory) => el("article", { class: "news-item" }, el("div", { class: "news-topline" }, el("span", { class: "finding-id" }, advisory.id), badge(advisory.severity), advisory.exploitation !== "none_known" ? badge(advisory.exploitation) : null), el("h3", {}, advisory.title), el("p", { class: compact ? "line-clamp" : "" }, advisory.summary), !compact ? el("div", { class: "news-dates muted" }, `Published ${date(advisory.published_at)} · Modified ${date(advisory.modified_at)} · Observed ${date(advisory.observed_at)}`, advisory.kev_added_at ? ` · KEV added ${date(advisory.kev_added_at)}` : "") : null, sourceLinks(advisory.sources)))); // Keep provenance and each distinct date beside its claim.
}

export function inventoryView(inventory) {
  // Global: visible collection completeness. Local: present raw observed versions without normalizing distro suffixes.
  if (!inventory) return empty("No device inventory yet", "A scan collects Windows applications, OS details, WSL distributions, and your configured project dependencies."); // Missing evidence is explicit.
  const search = el("input", { type: "search", placeholder: "Find an installed product or package…", "aria-label": "Search inventory", class: "search-input" }); // Let users inspect exact local evidence.
  const platform = select([["all", "Every platform"], ...[...new Set(inventory.assets.map((asset) => asset.platform))].map((name) => [name, name])], "all", { "aria-label": "Filter platform" }); // Derive scopes from actual inventory.
  const table = el("div"); // Keep potentially large package tables outside the filter controls.
  const render = () => { // Global: responsive inventory exploration. Local: page through matches instead of constructing thousands of rows.
    const filtered = inventory.assets.filter((asset) => (platform.value === "all" || asset.platform === platform.value) && `${asset.name} ${asset.version} ${asset.location}`.toLowerCase().includes(search.value.toLowerCase())); // Preserve exact package names and locations.
    let shown = 0; // A view-local cursor avoids server API complexity.
    const body = el("tbody"); // Render table rows incrementally.
    const count = el("div", { class: "table-count" }); // Explain the displayed subset explicitly.
    const more = button("Show more installations", () => append()); // Load another bounded batch on demand.
    const append = () => { // Global: practical large inventory support. Local: append only the next 100 rows.
      const batch = filtered.slice(shown, shown + 100); // Bound DOM work for large WSL inventories.
      body.append(...batch.map((asset) => el("tr", {}, el("td", {}, el("strong", {}, asset.name), el("div", { class: "muted table-meta break-word" }, asset.location || asset.kind)), el("td", { class: "mono" }, asset.version || "Unknown"), el("td", {}, asset.platform)))); // Locations remain inspectable text.
      shown += batch.length; count.textContent = `Showing ${shown} of ${filtered.length} installations`; more.hidden = shown >= filtered.length; // Never silently discard additional assets.
    };
    table.replaceChildren(filtered.length ? el("div", {}, el("div", { class: "table-scroll" }, el("table", {}, el("thead", {}, el("tr", {}, ["Installation", "Observed version", "Platform"].map((label) => el("th", {}, label)))), body)), el("div", { class: "table-pagination" }, count, more)) : empty("No matching installations", "Try another package name or platform.")); // Render a truthful filtered state.
    append(); // Fill the first page after the table exists.
  };
  [search, platform].forEach((control) => control.addEventListener("input", render)); render(); // Keep local filtering immediate.
  const coverage = el("div", { class: "coverage-grid" }, inventory.coverage.map((item) => el("article", { class: "coverage-card" }, el("div", { class: "coverage-card-top" }, el("h3", {}, item.component), badge(item.status)), el("p", {}, item.detail), el("span", { class: "muted" }, `${item.asset_count} observed assets`)))); // Errors and unsupported collectors stay first-class.
  return el("div", { class: "stack" }, panel("Collection coverage", `Snapshot captured ${date(inventory.captured_at, true)}`, coverage), panel("Observed installations", `${inventory.assets.length} assets across Windows, WSL, and selected projects`, el("div", {}, el("div", { class: "filter-toolbar" }, search, platform), table))); // Join completeness and inventory evidence.
}

export function historyView(runs, actions) {
  // Global: auditable scans and conversations. Local: expose failures and complete logs alongside successful summaries.
  if (!runs.length) return empty("No investigations yet", "Run a scan to start your local investigation history.", button("Run scan", actions.scan, "button button-primary")); // Real first-run state.
  return panel("Investigation history", "Every run keeps its status, summary, and complete log", el("div", { class: "history-list" }, runs.map((run) => el("article", { class: "history-item" }, el("div", { class: "history-top" }, el("div", {}, el("strong", {}, `${run.kind === "chat" ? "Agent conversation" : "Device scan"} · ${run.provider}`), el("div", { class: "muted table-meta" }, `${run.model} · ${date(run.started_at, true)}`)), badge(run.status)), run.summary ? el("p", {}, run.summary) : null, run.error ? el("pre", { class: "run-error" }, run.error) : null, el("div", { class: "history-footer" }, el("span", { class: "muted" }, run.finished_at ? `Finished ${date(run.finished_at)}` : "Run has not finished"), el("a", { href: `/api/runs/${encodeURIComponent(run.id)}/log`, class: "text-link", download: "" }, "Download full log ↗")))))); // Persisted evidence remains available after navigation.
}

export function showFinding(finding, actions) {
  // Global: make assessments reviewable. Local: every remediation remains text plus a copy action.
  const advisory = finding.advisory || {}; const asset = finding.asset || {}; const remediation = finding.remediation; // Preserve partial evidence if linked details are unavailable.
  const content = document.querySelector("#drawer-content"); // The shell owns one reusable modal drawer.
  content.replaceChildren(el("div", { class: "drawer-badges" }, badge(advisory.severity || "unknown"), badge(finding.status)), el("div", { class: "drawer-id mono" }, advisory.id || finding.advisory_id), el("h2", { id: "drawer-title" }, advisory.title || "Vulnerability assessment"), el("p", { class: "drawer-summary" }, advisory.summary || finding.rationale), el("div", { class: "asset-highlight" }, el("span", { class: "eyebrow" }, "OBSERVED INSTALLATION"), el("strong", {}, `${asset.name || finding.asset_id} ${asset.version || ""}`), el("span", {}, asset.platform || "Unknown platform"), asset.location ? el("small", { class: "break-word" }, asset.location) : null), el("section", { class: "drawer-section" }, el("h3", {}, "Why this assessment"), el("p", {}, finding.rationale), el("ul", {}, (finding.evidence || []).map((evidence) => el("li", {}, evidence))), finding.uncertainty ? el("div", { class: "uncertainty" }, el("strong", {}, "What remains uncertain"), el("p", {}, finding.uncertainty)) : null), remediation ? remediationSection(remediation) : el("section", { class: "drawer-section" }, el("h3", {}, "Proposed remediation"), el("p", { class: "muted" }, "No sufficiently supported fix was supplied for this finding.")), el("section", { class: "drawer-section" }, el("h3", {}, "Supporting sources"), sourceLinks([...(finding.sources || []), ...(advisory.sources || [])])), el("div", { class: "drawer-actions" }, button("Ask an agent about this finding ↗", () => actions.ask(finding), "button button-primary"), el("span", { class: "muted" }, `Checked ${date(finding.checked_at, true)}${finding.stale ? " · Earlier inventory" : ""}`))); // Build all rich content from text nodes.
  document.querySelector("#detail-drawer").hidden = false; document.querySelector("#drawer-backdrop").hidden = false; document.body.classList.add("drawer-open"); document.querySelector("#close-drawer").focus(); // Move keyboard focus into the modal.
}

function remediationSection(remediation) {
  // Global: make next steps practical. Local: expose context, elevation, reboot, and verification together.
  return el("section", { class: "drawer-section" }, el("h3", {}, "Proposed remediation"), el("p", {}, remediation.summary), el("div", { class: "remediation-meta" }, remediation.shell ? badge(remediation.shell, "context") : null, remediation.requires_admin ? badge("Administrator required", "medium") : null), remediation.steps?.length ? el("ol", {}, remediation.steps.map((step) => el("li", {}, step))) : null, (remediation.commands || []).map((command) => { const action = button("Copy", () => copy(command, action), "copy-button"); return el("div", { class: "command-block" }, action, el("pre", {}, el("code", {}, command))); }), el("p", { class: "muted" }, `Restart: ${remediation.reboot || "Unknown"}`), remediation.verification ? el("div", { class: "verification" }, el("strong", {}, "Verify the change"), el("p", {}, remediation.verification)) : null); // The interface has no execute-remediation operation.
}
