"""Global: durable local state. Local: small SQLite transactions and JSON-backed typed records.

Source: https://docs.python.org/3/library/sqlite3.html . The object table avoids an ORM for this
single-user app; boundary models validate records before they enter this store.
Alias semantics: https://ossf.github.io/osv-schema/#aliases-field . Multiple distinct CVEs
are conservatively treated as a shared notice, not equivalent vulnerability identities.
"""

import hashlib  # Deterministic occurrence IDs preserve findings across scans.
import json  # Typed records are stored as complete JSON documents.
import re  # Only exact CVE identifiers can select an unambiguous vulnerability identity.
import sqlite3  # SQLite coordinates the web process and optional scheduled scanner.
from contextlib import contextmanager  # Always close short-lived connections.
from pathlib import Path  # Database remains inside ignored workspace data.

from .models import Advisory, Inventory, Investigation, utc_now  # Shared wire contracts.


EXPLOITATION_STRENGTH = {"none_known": 0, "unverified_report": 1, "public_poc": 2, "known_exploited": 3}  # Ordinary enrichment can add evidence, but cannot implicitly retract it.


def _write_object(connection: sqlite3.Connection, category: str, identifier: str, body: dict, updated_at: str | None = None) -> None:
    """Global: reusable transactional upsert. Local: accept an existing transaction and preserve rekeyed observation time."""
    connection.execute("INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(category,id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at", (category, identifier, json.dumps(body, ensure_ascii=False), updated_at or utc_now()))  # SQL parameters preserve Unicode without interpolating data into code.


def _canonical(connection: sqlite3.Connection, identifier: str) -> str:
    """Global: resolve equivalent vulnerability names. Local: share the caller's transaction for consistent writes."""
    row = connection.execute("SELECT advisory_id FROM aliases WHERE alias=?", (identifier,)).fetchone()  # Indexed lookup contains equality mappings only.
    return row[0] if row else identifier  # Unseen source IDs remain independently addressable.


def _finding_id(advisory_id: str, asset_id: str) -> str:
    """Global: one finding per vulnerability and installation. Local: reuse exactly the same key when aliases merge."""
    return hashlib.sha256(f"{advisory_id}\0{asset_id}".encode()).hexdigest()[:24]  # A separator prevents ambiguous identity concatenation.


def _identifiers(record: dict) -> set[str]:
    """Global: retain all source identifiers. Local: display aliases need a separate equivalence check before registration."""
    return {record["id"], *record.get("aliases", [])}  # Source notice references remain visible even when unsafe to merge.


def _merge_advisories(records: list[dict], canonical: str) -> dict:
    """Global: combine evidence without weakening it. Local: later text wins while sources and established facts survive."""
    merged, sources, identifiers = {}, {}, set()  # Fold oldest existing records first and the incoming source last.
    for record in records:  # Record order controls ordinary text updates, not exploitation evidence strength.
        previous = merged  # Retain prior fields while applying the next complete source document.
        merged = {**previous, **record}  # Latest title, summary, and nonempty severity remain current.
        identifiers.update(_identifiers(record))  # Preserve original IDs after selecting a new canonical CVE.
        sources.update({source["url"]: source for source in record.get("sources", [])})  # Deduplicate citations by exact supporting URL.
        for field in ("published_at", "modified_at", "kev_added_at"):  # Missing enrichment dates cannot erase established dates.
            merged[field] = record.get(field) or previous.get(field, "")  # Keep disclosure and KEV addition as separate facts.
        merged["exploitation"] = max((previous.get("exploitation", "none_known"), record.get("exploitation", "none_known")), key=EXPLOITATION_STRENGTH.__getitem__)  # Preserve the strongest observed evidence category.
        if merged.get("severity", "unknown") == "unknown":  # An omitted categorical severity is not a correction.
            merged["severity"] = previous.get("severity", "unknown")  # Never manufacture a default severity.
    return {**merged, "id": canonical, "aliases": sorted(identifiers - {canonical}), "sources": list(sources.values()), "observed_at": utc_now()}  # Only advisory observation time changes during enrichment.


def _rekey_findings(connection: sqlite3.Connection, previous_ids: set[str], canonical: str) -> None:
    """Global: consolidate occurrences with their advisory. Local: the most recently checked assessment survives collisions."""
    if not previous_ids - {canonical}:  # The common hourly refresh keeps the same identity.
        return  # Avoid scanning findings for every unchanged feed record.
    winners, removals = {}, []  # Keep separate installations and remove obsolete identity hashes atomically.
    rows = connection.execute("SELECT id,body,updated_at FROM objects WHERE category='finding' ORDER BY updated_at,id").fetchall()  # This rare merge reads complete saved observations.
    for row in rows:  # Database identity changes must not count as reassessment.
        body = json.loads(row["body"])  # Preserve the original inventory snapshot, run, evidence, and timestamp.
        if body["advisory_id"] not in previous_ids | {canonical}:  # Unrelated vulnerability occurrences stay untouched.
            continue  # Only linked advisory records participate in collision resolution.
        identifier = _finding_id(canonical, body["asset_id"])  # Reuse the normal occurrence key to prevent future duplicate inserts.
        priority = (body.get("checked_at", row["updated_at"]), row["updated_at"], row["id"])  # Prefer the latest observation, with deterministic ties.
        if identifier not in winners or priority > winners[identifier][0]:  # Never revive an older affected or cleared assessment.
            winners[identifier] = (priority, {**body, "id": identifier, "advisory_id": canonical}, row["updated_at"])  # Preserve the winner's original timestamps.
        removals.append((row["id"],))  # Old and canonical collision rows are replaced by one winner.
    connection.executemany("DELETE FROM objects WHERE category='finding' AND id=?", removals)  # Removals roll back if any later merge write fails.
    for identifier, (_, body, updated_at) in winners.items():  # Write one occurrence per distinct installation.
        _write_object(connection, "finding", identifier, body, updated_at)  # Rekeying cannot make stale evidence look fresh.


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
            _write_object(connection, category, identifier, body)  # Reuse the same implementation for standalone and grouped writes.

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
            return _canonical(connection, identifier)  # Preserve exact case from sources.

    def save_advisory(self, advisory: Advisory) -> str:
        """Global: atomically join equivalent advisories and findings. Local: isolate multi-CVE notices and conflicting links."""
        incoming = advisory.model_dump(mode="json")  # Typed input becomes one source record in the evidence fold.
        identifiers = sorted(_identifiers(incoming))  # Deterministic parameter order makes identity selection reproducible.
        placeholders = ",".join("?" for _ in identifiers)  # Only placeholder count is constructed; identifiers remain SQL parameters.
        with self.connect() as connection:  # One connection replaces repeated per-alias reads and independent commits.
            connection.execute("BEGIN IMMEDIATE")  # Reserve the writer before identity reads; see https://www.sqlite.org/lang_transaction.html .
            rows = connection.execute(f"SELECT id,body FROM objects WHERE category='advisory' AND (id IN ({placeholders}) OR id IN (SELECT advisory_id FROM aliases WHERE alias IN ({placeholders}))) ORDER BY updated_at,id", [*identifiers, *identifiers]).fetchall()  # Include previously separate direct records as well as alias targets.
            records = [json.loads(row["body"]) for row in rows]  # Existing metadata is merged oldest first.
            discovered = set(identifiers).union(*(_identifiers(record) for record in records))  # Check the whole discovered identity group, including indirect CVEs.
            cves = sorted(value for value in discovered if re.fullmatch(r"CVE-\d{4}-\d{4,}", value))  # Same conservative rule as OSV normalization.
            if len(cves) > 1:  # A notice spanning multiple CVEs or conflicting aliases cannot establish equivalence.
                canonical = advisory.id  # Keep the source notice or conflicting CVE independently addressable.
                records = [record for record in records if record["id"] == canonical]  # Enrich only an existing exact source record.
                aliases = {canonical}  # Display source references but never register them as equality mappings.
            else:  # Only an unambiguous group can consolidate records and installation occurrences.
                canonical = cves[0] if cves else records[0]["id"] if records else advisory.id  # Prefer the sole CVE; otherwise retain an existing source identity.
                aliases = set(identifiers) | {record["id"] for record in records} | {canonical}  # Current verified links and former canonical IDs need redirects.
                for record in records:  # Retain only previously registered equivalences, not ambiguous display-only aliases.
                    aliases.update(row[0] for row in connection.execute("SELECT alias FROM aliases WHERE advisory_id=?", (record["id"],)))  # All historical safe aliases redirect to the survivor.
            previous_ids = {record["id"] for record in records}  # Deletion and occurrence rekeying share the same accepted identity group.
            body = _merge_advisories([*records, incoming], canonical)  # Preserve strongest exploitation, dates, and every source URL.
            body["aliases"] = sorted(set(body["aliases"]) | (aliases - {canonical}))  # Preserve older registered identifiers even if a source omitted them.
            _rekey_findings(connection, previous_ids, canonical)  # Merge occurrence collisions without altering assessment freshness.
            connection.executemany("DELETE FROM objects WHERE category='advisory' AND id=?", [(identifier,) for identifier in previous_ids - {canonical}])  # No duplicate superseded object remains in the dashboard.
            _write_object(connection, "advisory", canonical, body)  # Write the surviving advisory in the same transaction as its findings.
            connection.executemany("INSERT INTO aliases VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET advisory_id=excluded.advisory_id", [(value, canonical) for value in sorted(aliases)])  # Any failure rolls back the entire identity consolidation.
        return canonical  # Findings use the now-committed canonical identity.

    def save_investigation(self, run_id: str, result: Investigation) -> None:
        """Global: preserve findings between scans. Local: upsert only explicitly assessed occurrences."""
        for advisory in result.advisories:  # Intelligence records may legitimately have no local occurrence.
            self.save_advisory(advisory)  # Shared merging handles feed and model evidence.
        snapshot = self.get("inventory", run_id) or {"assets": []}  # Findings need their original installed facts.
        assets = {asset["id"]: asset for asset in snapshot["assets"]}  # Constant-time occurrence lookup.
        with self.connect() as connection:  # Serialize alias resolution and occurrence writes against other advisory merges.
            connection.execute("BEGIN IMMEDIATE")  # Another writer cannot rename a canonical ID between lookup and insertion.
            for finding in result.findings:  # Absent findings are retained, never silently marked fixed.
                canonical = _canonical(connection, finding.advisory_id)  # Merge OSV aliases with CVE intelligence using this transaction's view.
                identifier = _finding_id(canonical, finding.asset_id)  # Shared hashing also rekeys historical occurrences during a merge.
                _write_object(connection, "finding", identifier, {**finding.model_dump(mode="json"), "id": identifier, "advisory_id": canonical, "asset": assets.get(finding.asset_id), "run_id": run_id, "checked_at": utc_now()})  # Retain exact snapshot facts.

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
