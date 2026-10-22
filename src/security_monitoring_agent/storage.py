"""Global: durable local state. Local: small SQLite transactions and JSON-backed typed records.

Source: https://docs.python.org/3/library/sqlite3.html . The object table avoids an ORM for this
single-user app; boundary models validate records before they enter this store.
"""

import hashlib  # Deterministic occurrence IDs preserve findings across scans.
import json  # Typed records are stored as complete JSON documents.
import sqlite3  # SQLite coordinates the web process and optional scheduled scanner.
from contextlib import contextmanager  # Always close short-lived connections.
from pathlib import Path  # Database remains inside ignored workspace data.

from .models import Advisory, Inventory, Investigation, utc_now  # Shared wire contracts.


class Store:
    """Global: persistence facade. Local: separate reusable object/event operations from domain merges."""

    def __init__(self, path: Path):
        """Global: initialize a workspace database. Local: enable concurrent readers with WAL."""
        self.path = path  # Retain a path instead of sharing an unsafe connection across threads.
        path.parent.mkdir(parents=True, exist_ok=True)  # Create only the configured data directory.
        with self.connect() as connection:  # Schema creation is idempotent on restart.
            connection.execute("PRAGMA journal_mode=WAL")  # Readers do not block short writes.
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS objects (
                    category TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                    updated_at TEXT NOT NULL, PRIMARY KEY(category,id));
                CREATE TABLE IF NOT EXISTS aliases (alias TEXT PRIMARY KEY, advisory_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                    kind TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_run ON events(run_id,id);
            """)  # Separate event rows provide replay without loading full logs into memory.

    @contextmanager
    def connect(self):
        """Global: short transaction lifetime. Local: commit or rollback, then close every connection."""
        connection = sqlite3.connect(self.path, timeout=30)  # Wait for a brief competing writer.
        connection.row_factory = sqlite3.Row  # Named columns prevent positional decoding mistakes.
        try:  # Ensure all exceptional exits release the database handle.
            with connection:  # sqlite3 commits successful writes and rolls back failed ones.
                yield connection  # Domain operations share this narrow transaction scope.
        finally:  # The connection context alone does not close it.
            connection.close()  # Avoid leaking handles across hourly scans.

    def put(self, category: str, identifier: str, body: dict) -> None:
        """Global: common upsert. Local: values are SQL parameters, never interpolated SQL."""
        with self.connect() as connection:  # No network or subprocess work occurs in transactions.
            connection.execute("INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(category,id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at", (category, identifier, json.dumps(body, ensure_ascii=False), utc_now()))  # Preserve Unicode evidence.

    def get(self, category: str, identifier: str) -> dict | None:
        """Global: retrieve one document. Local: missing records remain explicitly absent."""
        with self.connect() as connection:  # Independent readers can run during a scan.
            row = connection.execute("SELECT body FROM objects WHERE category=? AND id=?", (category, identifier)).fetchone()  # Parameterized identity lookup.
        return json.loads(row["body"]) if row else None  # Do not synthesize a successful record.

    def all(self, category: str) -> list[dict]:
        """Global: list a document family. Local: newest updates appear first."""
        with self.connect() as connection:  # Fetch rows before closing the connection.
            rows = connection.execute("SELECT body FROM objects WHERE category=? ORDER BY updated_at DESC", (category,)).fetchall()  # Stable update ordering.
        return [json.loads(row["body"]) for row in rows]  # Return independent plain objects to callers.

    def update(self, category: str, identifier: str, **changes) -> dict:
        """Global: update owned records. Local: preserve fields not changed by a lifecycle transition."""
        body = self.get(category, identifier) or {"id": identifier}  # Run records are created before tasks start.
        body.update(changes)  # Callers own the record while performing transitions.
        self.put(category, identifier, body)  # Reuse the common short-transaction path.
        return body  # API handlers can return the exact persisted state.

    def event(self, run_id: str, kind: str, text: str) -> int:
        """Global: durable event cursor. Local: store complete text before publishing it."""
        with self.connect() as connection:  # Each event commits independently of a final finding.
            cursor = connection.execute("INSERT INTO events(run_id,kind,text,created_at) VALUES(?,?,?,?)", (run_id, kind, text, utc_now()))  # No size truncation.
            return int(cursor.lastrowid)  # SSE Last-Event-ID can resume from this exact cursor.

    def events(self, run_id: str, after: int = 0, limit: int = 200) -> list[dict]:
        """Global: bounded replay. Local: page complete records without shortening their payloads."""
        with self.connect() as connection:  # Polling is cheap through the composite index.
            rows = connection.execute("SELECT * FROM events WHERE run_id=? AND id>? ORDER BY id LIMIT ?", (run_id, after, limit)).fetchall()  # One cursor per run.
        return [dict(row) for row in rows]  # Native FastAPI SSE handles JSON serialization.

    def save_inventory(self, run_id: str, inventory: Inventory) -> None:
        """Global: evidence snapshots remain reproducible. Local: store the whole typed inventory."""
        self.put("inventory", run_id, {"run_id": run_id, **inventory.model_dump(mode="json")})  # Preserve capture time.

    def inventory(self) -> dict | None:
        """Global: show latest observed state. Local: retain coverage even if assessment later fails."""
        snapshots = self.all("inventory")  # Latest inventory can be partial and says so explicitly.
        return snapshots[0] if snapshots else None  # Empty state differs from an empty successful inventory.

    def canonical(self, identifier: str) -> str:
        """Global: resolve aliases. Local: fall back to the supplied stable advisory identifier."""
        with self.connect() as connection:  # Alias mappings are small indexed lookups.
            row = connection.execute("SELECT advisory_id FROM aliases WHERE alias=?", (identifier,)).fetchone()  # Preserve exact case from sources.
        return row[0] if row else identifier  # Unseen advisory IDs can be inserted later.

    def save_advisory(self, advisory: Advisory) -> str:
        """Global: merge source records without duplicate CVEs. Local: preserve KEV provenance."""
        identifiers = list(dict.fromkeys([advisory.id, *advisory.aliases]))  # Keep aliases without repetition.
        known = next((self.canonical(value) for value in identifiers if self.canonical(value) != value or self.get("advisory", value)), None)  # Prefer existing identity.
        canonical = known or next((value for value in identifiers if value.startswith("CVE-")), advisory.id)  # CVEs are convenient primary names.
        previous = self.get("advisory", canonical) or {}  # Corrections update one logical advisory.
        body = {**previous, **advisory.model_dump(mode="json"), "id": canonical, "observed_at": utc_now()}  # Latest source text wins.
        body["aliases"] = sorted(set(identifiers + previous.get("aliases", [])) - {canonical})  # Retain every discovered identifier.
        body["sources"] = list({source["url"]: source for source in previous.get("sources", []) + body["sources"]}.values())  # Merge provenance.
        for field in ("published_at", "modified_at", "kev_added_at"):  # Empty enrichment cannot erase known dates.
            body[field] = body[field] or previous.get(field, "")  # Unknown and absent are distinct.
        if previous.get("exploitation") == "known_exploited":  # A later generic model output cannot negate KEV.
            body["exploitation"] = "known_exploited"  # Preserve authoritative exploitation evidence.
        if body["severity"] == "unknown":  # Keep a previously established severity when enrichment omits it.
            body["severity"] = previous.get("severity", "unknown")  # Never manufacture a default severity.
        self.put("advisory", canonical, body)  # Commit the merged record before its alias references.
        with self.connect() as connection:  # Alias additions are a separate short batch.
            connection.executemany("INSERT INTO aliases VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET advisory_id=excluded.advisory_id", [(value, canonical) for value in [canonical, *body["aliases"]]])  # Resolve future occurrences.
        return canonical  # Findings use this stable identity.

    def save_investigation(self, run_id: str, result: Investigation) -> None:
        """Global: preserve findings between scans. Local: upsert only explicitly assessed occurrences."""
        for advisory in result.advisories:  # Intelligence records may legitimately have no local occurrence.
            self.save_advisory(advisory)  # Shared merging handles feed and model evidence.
        snapshot = self.get("inventory", run_id) or {"assets": []}  # Findings need their original installed facts.
        assets = {asset["id"]: asset for asset in snapshot["assets"]}  # Constant-time occurrence lookup.
        for finding in result.findings:  # Absent findings are retained, never silently marked fixed.
            canonical = self.canonical(finding.advisory_id)  # Merge OSV aliases with CVE intelligence.
            identifier = hashlib.sha256(f"{canonical}\0{finding.asset_id}".encode()).hexdigest()[:24]  # Stable per installation.
            self.put("finding", identifier, {**finding.model_dump(mode="json"), "id": identifier, "advisory_id": canonical, "asset": assets.get(finding.asset_id), "run_id": run_id, "checked_at": utc_now()})  # Retain exact snapshot facts.

    def advisories(self) -> list[dict]:
        """Global: intelligence view. Local: expose merged advisory records."""
        return self.all("advisory")  # News-window filtering belongs to the presentation/API layer.

    def findings(self) -> list[dict]:
        """Global: evidence-rich dashboard rows. Local: join advisories without losing installations."""
        latest = self.inventory()  # A newer snapshot means older unassessed findings are stale.
        rows = self.all("finding")  # Retain unresolved and explicitly cleared history alike.
        for row in rows:  # Enrichment does not modify persisted observations.
            row["advisory"] = self.get("advisory", row["advisory_id"])  # An unavailable advisory stays null.
            row["stale"] = bool(latest and row["run_id"] != latest["run_id"])  # Show reassessment gaps.
        return rows  # The UI filters by status instead of hiding uncertainty.
