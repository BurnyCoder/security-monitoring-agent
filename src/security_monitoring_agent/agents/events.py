"""Global: progress cannot masquerade as a valid scan. Local: parse CLI JSONL events.

Sources: https://code.claude.com/docs/en/headless and
https://developers.openai.com/codex/noninteractive .
"""

from collections.abc import Callable  # The app owns persistence and live delivery.
import json  # Provider protocols use newline-delimited JSON.

from .types import AgentResult  # Public output contract stays provider-independent.


class AgentEvents:
    """Global: normalize two streaming protocols. Local: accumulate only final evidence."""

    def __init__(self, provider: str, emit: Callable[[str, str], None]) -> None:
        """Global: a parser belongs to one invocation. Local: initialize isolated state."""
        self.provider = provider  # Select documented event semantics.
        self.emit = emit  # Emit derived text in addition to the runner's raw records.
        self.text = ""  # Last complete assistant message or native result.
        self.structured: dict | None = None  # Claude provides native structured output.
        self.session_id: str | None = None  # Resume only this invocation's session.
        self.model: str | None = None  # Do not invent observed provider metadata.
        self.finished = False  # A final result/turn event is required.
        self.error: str | None = None  # An error always overrides partial text.
        self.search_ids: set[str] = set()  # Partial and full tool messages can repeat.

    def feed(self, line: str) -> None:
        """Global: tolerate protocol extensions. Local: ignore unrecognized JSON events."""
        try:  # Some CLIs print startup diagnostics alongside protocol messages.
            event = json.loads(line)  # Raw lines are already logged by the runner.
        except (json.JSONDecodeError, ValueError):  # Non-JSON output is diagnostic only.
            return  # It must not become a fabricated final result.
        if not isinstance(event, dict):  # Only object events have protocol meaning.
            return  # Preserve compatibility with irrelevant JSON diagnostics.
        if self.provider == "claude":  # Claude's result and block protocol.
            self._claude(event)  # Keep provider details behind one dispatch point.
        else:  # The settings contract currently admits Codex as the other provider.
            self._codex(event)  # Codex uses turn and item completion events.

    def _tool(self, tool: dict) -> None:
        """Global: record actual search use. Local: deduplicate tool IDs across replays."""
        name = str(tool.get("name") or tool.get("type") or "")  # Both providers identify tools differently.
        if name in {"WebSearch", "web_search", "web_search_call"}:  # Count only observed search tools.
            identity = str(tool.get("id") or json.dumps(tool, sort_keys=True))  # Stable fallback for older events.
            if identity not in self.search_ids:  # Stream deltas and complete messages can repeat IDs.
                self.search_ids.add(identity)  # Count one emitted tool call once.
                self.emit("progress", "Searching the web")  # Show useful live activity.

    def _claude(self, event: dict) -> None:
        """Global: follow Claude's supported stream protocol. Local: collect blocks/result."""
        if event.get("session_id"):  # Metadata can accompany multiple event types.
            self.session_id = str(event["session_id"])  # Keep the exact resumable ID.
        if event.get("model"):  # Init events reveal the resolved alias.
            self.model = str(event["model"])  # Preserve the observed model version.
        kind = event.get("type")  # Dispatch on documented top-level event kind.
        if kind == "stream_event":  # Partial events provide immediate token progress.
            inner = event.get("event", {})  # Partial protocol wraps the native event.
            if inner.get("type") == "content_block_start":  # Tool identity appears at block start.
                self._tool(inner.get("content_block", {}))  # Count before full message arrives.
            delta = inner.get("delta", {})  # Text chunks have a separate delta envelope.
            if delta.get("type") == "text_delta":  # Do not treat tool JSON deltas as text.
                self.emit("agent_text", str(delta.get("text", "")))  # Stream every visible token.
        elif kind == "assistant":  # Full messages include tools and resolved model metadata.
            message = event.get("message", {})  # Claude wraps message fields here.
            if message.get("model"):  # Later events can reflect a provider fallback.
                self.model = str(message["model"])  # Latest observed model wins.
            for block in message.get("content", []):  # Both tool and text blocks may coexist.
                if isinstance(block, dict):  # Ignore non-object compatibility additions.
                    self._tool(block)  # Deduplication prevents double-counting partial events.
        elif kind == "result":  # Only this event closes a successful Claude turn.
            self.finished = True  # Record terminal state independently of usable data.
            self.text = str(event.get("result") or "")  # Preserve complete final text.
            value = event.get("structured_output")  # Native schema output can be absent.
            self.structured = value if isinstance(value, dict) else None  # Application schema requires an object.
            if event.get("is_error") or str(event.get("subtype", "")).startswith("error"):
                self.error = self.text or json.dumps(event.get("errors", event), ensure_ascii=False)  # Retain complete provider diagnostics.

    def _codex(self, event: dict) -> None:
        """Global: follow Codex exec JSONL. Local: identify thread, tools, and final turn."""
        kind = event.get("type")  # Codex emits item and turn lifecycle events.
        if event.get("model"):  # Preserve model metadata when a version emits it.
            self.model = str(event["model"])  # Missing metadata stays unknown.
        if kind == "thread.started":  # New invocation announces its resume identity.
            self.session_id = event.get("thread_id")  # Never use a global most-recent session.
        elif kind in {"item.started", "item.updated", "item.completed"}:  # Tools can report several states.
            item = event.get("item", {})  # Common item envelope.
            self._tool(item)  # Record web use at first observation.
            if kind == "item.completed" and item.get("type") == "agent_message":  # Completed prose is coherent.
                self.text = str(item.get("text", ""))  # Native final file later takes precedence.
                self.emit("agent_text", self.text)  # Publish complete text without truncation.
        elif kind == "turn.completed":  # Success requires explicit turn completion.
            self.finished = True  # A partial assistant message alone is insufficient.
        elif kind in {"turn.failed", "error"}:  # CLI errors can still use exit-zero transports.
            value = event.get("error", event.get("message", event))  # Support both documented error envelopes.
            self.error = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)  # Keep exact diagnostic content.

    def finish(self, *, require_structured: bool = False, final_text: str | None = None) -> AgentResult:
        """Global: validate the terminal boundary. Local: reject partial/refused results."""
        if self.error:  # Failed output must not become a clean scan.
            raise RuntimeError(self.error)  # Caller persists the failure with raw logs.
        if not self.finished:  # A killed CLI may leave useful but incomplete progress.
            raise RuntimeError("Agent ended without a final completion event")  # Report incomplete work explicitly.
        text = final_text if final_text is not None else self.text  # Codex's native file is authoritative.
        structured = self.structured  # Claude's schema tool supplies its native result.
        if self.provider == "codex" and require_structured:  # Schema-constrained Codex output is JSON text.
            try:  # No greedy brace extraction that could conceal malformed output.
                value = json.loads(text)  # Parse the entire returned document.
            except (json.JSONDecodeError, ValueError) as error:  # Invalid JSON is not zero findings.
                raise RuntimeError("Agent final response is not valid JSON") from error  # Preserve parse cause.
            structured = value if isinstance(value, dict) else None  # The investigation schema is an object.
        if require_structured and structured is None:  # A refusal may omit structured_output.
            raise RuntimeError("Agent ended without the required structured output")  # Keep missing data visible.
        if not text and structured is None:  # Empty successful metadata is not an answer.
            raise RuntimeError("Agent ended without a final response")  # Chat must receive actual output.
        return AgentResult(text or json.dumps(structured, ensure_ascii=False), structured, self.session_id, self.model, len(self.search_ids))  # One provider-neutral result.
