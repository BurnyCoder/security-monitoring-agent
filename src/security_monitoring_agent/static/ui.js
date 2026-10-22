// Global: reusable safe DOM primitives. Local: all server and model text uses textContent; https://developer.mozilla.org/en-US/docs/Web/API/Document/createElement.
export function el(tag, attributes = {}, ...children) {
  // Global: avoid duplicated rendering and unsafe HTML. Local: build elements with native DOM methods.
  const node = document.createElement(tag); // Select only application-defined element names.
  Object.entries(attributes).forEach(([key, value]) => { // Apply fixed attribute names and escaped values.
    if (key === "class") node.className = value; // Class names come from application mappings.
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value); // Register actual callbacks instead of inline handlers.
    else if (key === "text") node.textContent = value; // Treat model content as text, never markup.
    else if (key === "checked" || key === "disabled" || key === "hidden") node[key] = Boolean(value); // Preserve boolean form semantics.
    else if (value !== null && value !== undefined) node.setAttribute(key, value); // Other HTML attributes are text.
  });
  children.flat(Infinity).forEach((child) => { if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child))); }); // Safely compose child text and elements.
  return node; // Return a reusable element to the caller.
}

export function button(text, handler, className = "button button-secondary") {
  // Global: shared button behavior. Local: type prevents unintended form submission.
  return el("button", { type: "button", class: className, onclick: handler }, text); // Bind a safe click callback.
}

export function badge(value, kind = value) {
  // Global: consistent status language. Local: map technical enums to readable labels.
  const labels = { potentially_affected: "Potentially affected", not_affected: "Not affected", known_exploited: "Known exploited", public_poc: "Public PoC", unverified_report: "Unverified report", none_known: "No known exploit", ok: "Covered", partial: "Partial", error: "Unavailable", unsupported: "Unsupported", succeeded: "Completed", completed: "Completed", running: "Running", cancelled: "Stopped", interrupted: "Interrupted", failed: "Failed", pending: "Queued", queued: "Queued" }; // Keep source uncertainty visible.
  return el("span", { class: `badge badge-${String(kind).replace(/[^a-z_]/gi, "")}` }, labels[value] || String(value || "Unknown").replace(/^./, (c) => c.toUpperCase())); // Only mapped styling can affect appearance.
}

export function date(value, full = false) {
  // Global: local presentation of stored UTC evidence. Local: missing dates remain explicitly unknown.
  const parsed = value ? new Date(value) : null; // Parse only supplied timestamps.
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleString(undefined, full ? { dateStyle: "medium", timeStyle: "short" } : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "Not available"; // Do not fabricate a current timestamp.
}

export function empty(title, description, action = null) {
  // Global: real empty states. Local: explain next action without synthetic findings.
  return el("div", { class: "empty-state" }, el("span", { class: "empty-icon", "aria-hidden": "true" }, "◎"), el("h3", {}, title), el("p", {}, description), action); // Keep all states readable with or without an action.
}

export function panel(title, subtitle, content, trailing = null) {
  // Global: consistent content hierarchy. Local: one shared card layout for every subsystem.
  return el("section", { class: "panel" }, el("div", { class: "panel-heading" }, el("div", {}, el("h2", {}, title), subtitle ? el("p", {}, subtitle) : null), trailing), content); // Build semantic section and heading elements.
}

export function sourceLinks(sources = []) {
  // Global: evidence remains inspectable. Local: allow only HTTP(S) references, matching the backend contract.
  const unique = [...new Map(sources.filter((source) => /^https?:\/\//i.test(source.url || "")).map((source) => [source.url, source])).values()]; // Deduplicate shared advisory and applicability citations.
  return el("div", { class: "source-links" }, unique.map((source) => el("a", { href: source.url, target: "_blank", rel: "noopener noreferrer" }, source.title || source.url, " ↗"))); // External references never become executable schemes.
}

export function labeled(label, control, hint = "") {
  // Global: accessible settings fields. Local: nested labels associate controls without generated IDs.
  return el("label", { class: "form-field" }, el("span", {}, label), control, hint ? el("small", {}, hint) : null); // Group label, field and help text.
}

export function select(options, value, attributes = {}) {
  // Global: shared native select construction. Local: preserve keyboard interaction and arbitrary model input elsewhere.
  const node = el("select", attributes, options.map(([key, label]) => el("option", { value: key }, label))); // Build only supplied choices.
  node.value = String(value); // Select the persisted choice after options exist.
  return node; // Hand control ownership back to the form.
}

export async function copy(text, target) {
  // Global: proposed fixes are copyable only. Local: use the browser clipboard without executing commands; https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText.
  try { await navigator.clipboard.writeText(text); target.textContent = "Copied"; setTimeout(() => { target.textContent = "Copy"; }, 1800); } // Confirm successful copying briefly.
  catch { target.textContent = "Select text to copy"; } // Keep the complete command visible if clipboard access fails.
}
