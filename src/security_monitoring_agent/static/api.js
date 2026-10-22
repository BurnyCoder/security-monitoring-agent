// Global: same-origin API transport. Local: use native fetch and EventSource; https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API.
export async function request(path, options = {}) {
  // Global: consistent failures across views. Local: JSON bodies remain structured, never shell strings.
  const init = { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } }; // Preserve optional caller headers.
  if (options.body !== undefined) init.body = JSON.stringify(options.body); // Serialize one API payload.
  const response = await fetch(`/api${path}`, init); // Keep authentication and routing on the local origin.
  const contentType = response.headers.get("content-type") || ""; // Handle backend text errors as well as JSON.
  const data = contentType.includes("json") ? await response.json() : await response.text(); // Read the response once.
  if (!response.ok) throw new Error(typeof data === "string" ? data : typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data)); // Expose actionable diagnostics.
  return data; // Return the typed wire contract to its view.
}

export function streamRun(runId, onEvent) {
  // Global: real-time activity without coupling scan lifetime to a tab. Local: native EventSource reconnects automatically; https://developer.mozilla.org/en-US/docs/Web/API/EventSource.
  const stream = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events`); // Use the server's event cursor protocol.
  stream.onmessage = (message) => { // Decode each complete application event.
    try { onEvent(JSON.parse(message.data)); } catch (error) { console.warn("Unrecognized activity event", error); } // A malformed progress event does not corrupt findings.
  };
  return stream; // The orchestrator closes this stream when the run finishes or changes.
}
