"""Global: complete audit trail. Local: one event sink fans out to file, SQLite and terminal.

Source: https://docs.python.org/3/library/json.html . JSONL preserves embedded newlines and Unicode.
"""

import json  # A serialized event is one physical log line regardless of its text length.
import threading  # Concurrent stdout/stderr readers share this sink safely.
import sys  # Background pythonw tasks intentionally have no terminal stream.
from pathlib import Path  # Log paths are derived from owned run IDs.

from .models import utc_now  # All sinks use the same timestamp representation.
from .storage import Store  # SSE replays persisted event IDs rather than volatile queues.


class RunLog:
    """Global: reusable run transcript. Local: never shorten prompts or emitted output."""

    def __init__(self, root: Path, store: Store, run_id: str):
        """Global: create one local transcript per run. Local: prepare an ignored log directory."""
        self.store, self.run_id = store, run_id  # Event identity is fixed for the lifetime of a run.
        self.lock = threading.Lock()  # Make each multiplexer write indivisible within the process.
        directory = root / "logs"  # Credentials and device evidence never enter the tracked tree.
        directory.mkdir(exist_ok=True)  # Preserve every prior run's complete transcript.
        self.path = directory / f"{run_id}.jsonl"  # Run IDs already contain UTC timestamp and randomness.

    def __call__(self, kind: str, text: str) -> None:
        """Global: realtime observability. Local: durable writes precede terminal/UI notification."""
        stamp = utc_now()  # Timestamp each emitted event, not just the final response.
        with self.lock:  # Concurrent streams cannot interleave partial JSON records.
            with self.path.open("a", encoding="utf-8") as handle:  # Closing flushes each complete event.
                handle.write(json.dumps({"created_at": stamp, "run_id": self.run_id, "kind": kind, "text": text}, ensure_ascii=False) + "\n")  # No truncation.
            self.store.event(self.run_id, kind, text)  # Persist before an SSE client can observe the event.
            if sys.stdout is not None:  # File and database logging still work in background mode.
                print(f"[{stamp}] [{self.run_id}] [{kind}] {text}", flush=True)  # Full live terminal output.
