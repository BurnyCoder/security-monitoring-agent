"""Global: agent output is evidence, not success by default. Local: parser fixtures.

Sources: https://code.claude.com/docs/en/headless and
https://developers.openai.com/codex/noninteractive .
"""

import asyncio  # Provider invocation shares the application's cancellation event.
import json  # Replay the actual JSONL event shape.
from pathlib import Path  # Temporary output files remain local.

import pytest  # Behavioral regression checks.

from security_monitoring_agent.agents.events import AgentEvents  # Parser under test.
from security_monitoring_agent.agents.commands import command  # Literal provider CLI boundary.
from security_monitoring_agent.agents import run_agent  # Public invocation facade.
from security_monitoring_agent.models import Settings  # Real configuration contract.
from security_monitoring_agent.process import ProcessResult  # Fake transport result only.


def test_claude_structured_result_and_search_deduplication() -> None:
    """Global: only a final result is authoritative. Local: deduplicate streamed tools."""
    events = AgentEvents("claude", lambda kind, text: None)  # Quiet transport callback.
    events.feed(json.dumps({"type": "system", "subtype": "init", "session_id": "session", "model": "haiku-version"}))  # Actual selection metadata.
    tool = {"type": "tool_use", "id": "search-1", "name": "WebSearch", "input": {"query": "CVE"}}  # One search appears in two stream forms.
    events.feed(json.dumps({"type": "stream_event", "event": {"type": "content_block_start", "content_block": tool}}))  # Incremental tool start.
    events.feed(json.dumps({"type": "assistant", "message": {"content": [tool]}}))  # Complete replay must not count twice.
    events.feed(json.dumps({"type": "result", "is_error": False, "result": "Complete", "structured_output": {"summary": "Evidence"}}))  # Final schema field.
    result = events.finish(require_structured=True)  # Production validation boundary.
    assert result.structured == {"summary": "Evidence"}  # Preserve native structured output.
    assert (result.web_searches, result.session_id, result.model) == (1, "session", "haiku-version")  # Metadata remains accurate.


@pytest.mark.parametrize("event", [{"type": "result", "is_error": True, "result": "Authentication required"}, {"type": "result", "is_error": False, "result": "I cannot return findings"}])
def test_claude_missing_or_failed_output_is_not_success(event: dict) -> None:
    """Global: refusal cannot mean clean device. Local: reject unusable final output."""
    events = AgentEvents("claude", lambda kind, text: None)  # No raw transport in unit fixtures.
    events.feed(json.dumps(event))  # Replay failure or missing schema result.
    with pytest.raises(RuntimeError):  # Neither case may silently produce zero findings.
        events.finish(require_structured=True)  # Require schema for a scan.


def test_codex_items_preserve_result_and_unknown_events() -> None:
    """Global: provider additions are compatible. Local: parse known final item only."""
    events = AgentEvents("codex", lambda kind, text: None)  # Ignore optional progress.
    events.feed("not-json diagnostic")  # Raw logs preserve this elsewhere.
    events.feed(json.dumps({"type": "future.event", "x": 1}))  # Ignore unknown event kind.
    events.feed(json.dumps({"type": "thread.started", "thread_id": "thread"}))  # Explicit resume identity.
    events.feed(json.dumps({"type": "item.completed", "item": {"id": "tool", "type": "web_search", "query": "CVE"}}))  # Evidence of live search.
    events.feed(json.dumps({"type": "item.completed", "item": {"id": "answer", "type": "agent_message", "text": '{"summary":"Done"}'}}))  # Final message text.
    events.feed(json.dumps({"type": "turn.completed", "usage": {}}))  # Explicit successful turn.
    result = events.finish(require_structured=True)  # Parse native JSON without greedy extraction.
    assert result.structured == {"summary": "Done"}  # No parser-invented findings.
    assert (result.web_searches, result.session_id) == (1, "thread")  # Keep provenance.


def test_codex_partial_message_cannot_substitute_for_completion() -> None:
    """Global: a crash is not a successful assessment. Local: require terminal evidence."""
    events = AgentEvents("codex", lambda kind, text: None)  # No transport needed for this failure fixture.
    events.feed(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "Partial findings"}}))  # Model spoke before a disconnect.
    with pytest.raises(RuntimeError, match="completion event"):  # Do not silently publish partial results.
        events.finish()  # A final assistant message is insufficient on its own.


def test_claude_command_reuses_login_and_keeps_models_literal(tmp_path: Path) -> None:
    """Global: preserve subscription auth and model choice. Local: verify standalone argv."""
    model = "custom-model; literal"  # Even unusual IDs must never become shell commands.
    args = command(Settings(provider="claude", model=model), tmp_path, {"type": "object"}, "explicit-session")  # Build without inference.
    assert args[args.index("--model") + 1] == model  # No interpolation or shell splitting.
    assert "--bare" not in args and "--dangerously-skip-permissions" in args  # Reuse OAuth with requested execution permissions.
    assert json.loads(args[args.index("--settings") + 1]) == {"sandbox": {"enabled": False}}  # Explicit shell sandbox setting.
    assert args[args.index("--resume") + 1] == "explicit-session"  # Never infer a global last session.
    assert "--json-schema" in args and "--include-partial-messages" in args  # Structured result and live progress share the run.


@pytest.mark.asyncio
async def test_codex_resume_uses_stdin_and_supported_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Global: chat stays in its own session. Local: check argv without paid inference."""
    recorded = {}  # Capture transport boundary rather than launching an agent.
    async def fake_process(args: list[str], **kwargs) -> ProcessResult:
        """Global: deterministic CLI contract test. Local: simulate a completed turn."""
        recorded.update(args=args, **kwargs)  # Preserve argv and stdin for assertions.
        output = Path(args[args.index("--output-last-message") + 1])  # Provider's final output artifact.
        output.write_text("A complete answer", encoding="utf-8")  # Simulate Codex's native file.
        kwargs["emit"]("stdout", '{"type":"turn.completed"}\n')  # Successful final event.
        return ProcessResult(0, "", "")  # The raw output was already streamed.
    monkeypatch.setattr("security_monitoring_agent.agents.runner.run_process", fake_process)  # Isolate only transport.
    result = await run_agent(Settings(), "literal `prompt`", tmp_path, lambda kind, text: None, asyncio.Event(), session_id="thread-id")  # Explicit resume.
    assert "resume" in recorded["args"] and "thread-id" in recorded["args"]  # Exact thread, never --last.
    assert "--dangerously-bypass-approvals-and-sandbox" in recorded["args"]  # User-requested execution mode.
    assert 'web_search="live"' in recorded["args"]  # Global config works for exec and resume.
    assert "--cd" not in recorded["args"] and "--color" not in recorded["args"]  # Unsupported resume flags omitted.
    assert recorded["stdin"] == "literal `prompt`"  # Prompt bypasses shell parsing.
    assert result.text == "A complete answer"  # Native result file takes precedence.
