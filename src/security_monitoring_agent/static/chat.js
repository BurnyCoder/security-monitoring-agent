// Global: evidence-aware follow-up conversations. Local: use persisted chat sessions and the same run stream; https://developer.mozilla.org/en-US/docs/Web/API/HTMLTextAreaElement.
import { request } from "./api.js"; // Share local transport with scans.
import { el, button, panel, empty, date, select } from "./ui.js"; // Reuse escaped text rendering.

export async function chatView(settings, actions, selectedId = null, findingId = null) {
  // Global: one conversation per deliberate context. Local: never resume an unrelated provider session implicitly.
  let chats = await request("/chats"); let currentId = selectedId; let currentRun = null; let loading = false; let signature = ""; let loadVersion = 0; // Track the selected chat independently from concurrent scans.
  const provider = select([["codex", "Codex"], ["claude", "Claude Code"]], settings.provider, { "aria-label": "Conversation provider" }); // Existing chats retain their original provider.
  const model = el("input", { value: settings.model, list: "model-suggestions", "aria-label": "Conversation model", placeholder: "Model identifier" }); // Free model selection matches scan controls.
  provider.addEventListener("change", () => { model.value = provider.value === "claude" ? "haiku" : "gpt-6-luna"; }); // Offer tested defaults without restricting model IDs.
  const list = el("div", { class: "chat-list" }); const messages = el("div", { class: "chat-messages", "aria-live": "polite" }); // Separate navigation from the conversation transcript.
  const context = el("div", { class: "chat-context" }, "New conversation · Ask about a finding or your device's exposure"); // State which evidence context is active.
  const input = el("textarea", { rows: 3, placeholder: "Ask about a vulnerability, a proposed fix, or your device…", required: "", "aria-label": "Message to agent" }); // Multiline prompts are preserved.
  const send = el("button", { type: "submit", class: "button button-primary" }, "Send message ↗"); // Use form submission for keyboard support.
  const logLink = el("a", { class: "text-link", download: "", hidden: true }, "Full log ↗"); // Keep the selected chat log accessible even when a scan owns the overview stream.
  const stop = button("Stop", async () => { if (!currentRun) return; stop.disabled = true; try { await request(`/runs/${encodeURIComponent(currentRun.id)}/cancel`, { method: "POST" }); await load(currentId); } catch (error) { actions.error(error); } finally { stop.disabled = false; } }, "button button-secondary"); // Cancel this conversation's run without interrupting a simultaneous scan.
  const activity = el("div", { id: "chat-activity", class: "chat-activity", hidden: true }, el("span", { class: "live-pill" }, "WORKING"), el("span", {}, "The agent is investigating. Its answer will appear here."), logLink, stop); // A running turn remains explicit until its final answer is persisted.
  const drawList = () => { // Global: durable conversation selection. Local: show identity and date instead of invented titles.
    list.replaceChildren(...chats.map((chat) => button(`${chat.finding_id ? "Finding discussion" : "Device investigation"}\n${chat.provider} · ${date(chat.created_at)}`, () => load(chat.id), `chat-list-item${chat.id === currentId ? " selected" : ""}`))); // Render each persisted chat as a native button.
    if (!chats.length) list.append(el("p", { class: "quiet-empty" }, "Your conversations will appear here.")); // Provide an honest first-use state.
  };
  const load = async (id) => { // Global: load one explicit thread. Local: preserve provider/model and server-side session binding.
    if (!id) return; const version = ++loadVersion; loading = true; // A deliberate thread selection supersedes an older in-flight response.
    try { // Keep transport errors inside the view rather than unhandled callback rejections.
      const detail = await request(`/chats/${encodeURIComponent(id)}`); if (version !== loadVersion) return; currentId = id; actions.selected(id); provider.value = detail.chat.provider; model.value = detail.chat.model; provider.disabled = true; model.disabled = true; // Existing conversation identity cannot silently change.
      context.textContent = `${detail.chat.provider} · ${detail.chat.model}${detail.chat.finding_id ? " · Linked to a device finding" : " · Device investigation"}`; // Explain active context.
      const nextSignature = `${id}:${detail.messages.length}:${detail.messages.at(-1)?.created_at || ""}`; // Persisted messages only append, so this detects visible transcript changes.
      if (signature !== nextSignature) { messages.replaceChildren(...detail.messages.map((message) => el("article", { class: `chat-message ${message.role === "user" ? "from-user" : "from-agent"}` }, el("div", { class: "message-heading" }, el("strong", {}, message.role === "user" ? "You" : "Agent"), el("time", {}, date(message.created_at))), el("div", { class: "message-content" }, message.content)))); if (!detail.messages.length) messages.append(empty("What would you like to investigate?", "Ask for the evidence behind an assessment, a more precise fix, or a follow-up check.")); messages.scrollTop = messages.scrollHeight; signature = nextSignature; } // Preserve scroll position and draft text when a polling response has no new message.
      currentRun = detail.active_run; activity.hidden = !currentRun; send.disabled = Boolean(currentRun); if (currentRun) { logLink.href = `/api/runs/${encodeURIComponent(currentRun.id)}/log`; logLink.hidden = false; } drawList(); // Chat progress stays correct while the main dashboard follows a scan.
    } catch (error) { actions.error(error); } // Surface API failures without losing the current prompt.
    finally { if (version === loadVersion) loading = false; } // Do not release a newer request's loading state.
  };
  const newChat = () => { // Global: intentional fresh conversations. Local: clear thread identity while leaving history intact.
    loadVersion += 1; loading = false; currentId = null; currentRun = null; signature = ""; findingId = null; actions.selected(null); provider.disabled = false; model.disabled = false; context.textContent = "New conversation · Ask about a finding or your device's exposure"; messages.replaceChildren(empty("Start with a question", "Your agent can inspect current scan evidence and search for more information.")); activity.hidden = true; send.disabled = false; drawList(); input.focus(); // Reset only this view's draft context; an existing background chat keeps running.
  };
  const form = el("form", { class: "chat-composer" }, input, el("div", { class: "composer-footer" }, el("span", { class: "muted" }, "Enter to send · Shift + Enter for a new line"), send)); // Match familiar chat keyboard behavior.
  input.addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); if (!send.disabled && input.value.trim()) form.requestSubmit(); } }); // Do not submit empty or concurrent prompts.
  form.addEventListener("submit", async (event) => { // Global: persist prompt before starting the provider run. Local: create a conversation only when needed.
    event.preventDefault(); const message = input.value.trim(); if (!message || currentRun || send.disabled) return; send.disabled = true; // Serialize this chat's messages while allowing a parallel scan.
    try { // Preserve the draft if either creation or dispatch fails.
      if (!currentId) { const chat = await request("/chats", { method: "POST", body: { provider: provider.value, model: model.value.trim(), ...(findingId ? { finding_id: findingId } : {}) } }); currentId = chat.id; actions.selected(currentId); chats = [chat, ...chats]; } // Bind optional finding context to the new session.
      const run = await request(`/chats/${encodeURIComponent(currentId)}/messages`, { method: "POST", body: { message } }); currentRun = run; input.value = ""; actions.started(run); await load(currentId); // Record local ownership immediately, then render the persisted prompt and live status.
    } catch (error) { actions.error(error); send.disabled = false; } // Keep a retry possible after a rejected request.
  });
  drawList(); if (currentId) await load(currentId); else messages.append(empty(findingId ? "Investigate this finding" : "Ask your security agent", findingId ? "This conversation will include the selected finding and its local evidence." : "Explore the evidence, understand a proposed fix, or ask what to check next.")); // Initialize the selected or new conversation.
  send.disabled = Boolean(currentRun); // A simultaneous scan does not block a follow-up conversation.
  const view = el("div", { class: "chat-layout" }, panel("Conversations", "Local investigation history", el("div", {}, el("div", { class: "chat-new" }, button("+ New conversation", newChat, "button button-secondary")), list)), el("section", { class: "panel chat-panel" }, el("div", { class: "chat-toolbar" }, provider, model), context, messages, activity, form)); // Keep the composer reachable while the transcript scrolls.
  view.refreshConversation = () => currentId ? load(currentId) : Promise.resolve(); // Let the orchestrator refresh completed answers without destroying a typed draft.
  const polling = setInterval(() => { if (!view.isConnected) { clearInterval(polling); return; } if (currentId && !loading) load(currentId); }, 4000); // Selected-chat polling discovers completion even when /status prioritizes a concurrent scan; release the timer on navigation.
  return view; // The application owns route mounting and scan lifecycle.
}
