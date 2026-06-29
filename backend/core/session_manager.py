"""SQLite session CRUD + state machine with AI decision logging."""
import aiosqlite
import uuid
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from models.session import Session, Finding

logger = logging.getLogger(__name__)


def _safe_json_loads(value: Any, default: Any = None) -> Any:
    """Safely parse JSON, returning default for null/empty/invalid strings."""
    if value is None or value == "":
        return default if default is not None else {}
    try:
        parsed = json.loads(value)
        if default is not None and not isinstance(parsed, type(default)):
            return default
        return parsed
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


class SessionManager:
    def __init__(self, db_path: str):
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self):
        """Initialize database with schema and apply lightweight migrations."""
        init_sql_path = Path(__file__).parent.parent / "data" / "init_sessions.sql"
        async with aiosqlite.connect(self._db_path) as db:
            with open(init_sql_path, "r") as f:
                await db.executescript(f.read())
            await db.commit()
            # Lightweight migrations for existing databases
            await self._add_column_if_missing(db, "ai_decisions", "input_tokens", "INTEGER DEFAULT 0")
            await self._add_column_if_missing(db, "ai_decisions", "output_tokens", "INTEGER DEFAULT 0")
        logger.info("Session database initialized")

    async def _add_column_if_missing(self, db, table: str, column: str, definition: str):
        """Add a column to a table if it does not already exist."""
        cursor = await db.execute(f"PRAGMA table_info({table})")
        rows = await cursor.fetchall()
        if any(row[1] == column for row in rows):
            return
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        await db.commit()

    async def create_session(self, target: str, test_type: str = "web_app", scope: list = None, metadata: dict = None) -> str:
        """Create a new session and return session_id."""
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO sessions (session_id, target, test_type, scope, metadata, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (session_id, target, test_type, json.dumps(scope or []), json.dumps(metadata or {}), "initialized")
            )
            await db.commit()
        logger.info(f"Created session {session_id} for {target}")
        return session_id

    async def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve session by ID."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            )
            row = await cursor.fetchone()
            if row:
                return Session(
                    session_id=row["session_id"],
                    target=row["target"],
                    test_type=row["test_type"],
                    scope=_safe_json_loads(row["scope"], default=[]),
                    status=row["status"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    findings_count=row["findings_count"],
                    metadata=_safe_json_loads(row["metadata"], default={}),
                )
            return None

    async def list_sessions(self) -> List[Session]:
        """List all sessions ordered by created_at descending."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC"
            )
            rows = await cursor.fetchall()
            sessions = []
            for row in rows:
                sessions.append(Session(
                    session_id=row["session_id"],
                    target=row["target"],
                    test_type=row["test_type"],
                    scope=_safe_json_loads(row["scope"], default=[]),
                    status=row["status"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    findings_count=row["findings_count"],
                    metadata=_safe_json_loads(row["metadata"], default={}),
                ))
            return sessions

    async def update_session_status(self, session_id: str, status: str):
        """Update session status."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE sessions SET status = ? WHERE session_id = ?",
                (status, session_id)
            )
            await db.commit()

    async def update_session_metadata(self, session_id: str, metadata: dict):
        """Merge metadata into an existing session."""
        session = await self.get_session(session_id)
        if not session:
            return
        updated = dict(session.metadata or {})
        updated.update(metadata)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE sessions SET metadata = ? WHERE session_id = ?",
                (json.dumps(updated), session_id)
            )
            await db.commit()

    async def add_finding(self, finding: Finding) -> str:
        """Add a finding to a session."""
        finding_id = f"find-{uuid.uuid4().hex[:8]}"
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO findings 
                   (id, session_id, attack_type, confidence, endpoint, parameter, 
                    evidence, status, cvss_score, severity, remediation, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, finding.session_id, finding.attack_type, finding.confidence,
                 finding.endpoint, finding.parameter, finding.evidence, finding.status,
                 finding.cvss_score, finding.severity, finding.remediation, 
                 json.dumps(finding.metadata))
            )
            await db.commit()
        return finding_id

    async def get_findings(self, session_id: str, status: Optional[str] = None) -> List[Finding]:
        """Get findings for a session, optionally filtered by status."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            if status:
                cursor = await db.execute(
                    "SELECT * FROM findings WHERE session_id = ? AND status = ? ORDER BY created_at",
                    (session_id, status)
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at",
                    (session_id,)
                )
            rows = await cursor.fetchall()
            findings = []
            for row in rows:
                findings.append(Finding(
                    session_id=row["session_id"],
                    attack_type=row["attack_type"],
                    confidence=row["confidence"],
                    endpoint=row["endpoint"],
                    parameter=row["parameter"],
                    evidence=row["evidence"],
                    status=row["status"],
                    cvss_score=row["cvss_score"],
                    severity=row["severity"],
                    remediation=row["remediation"],
                    metadata=_safe_json_loads(row["metadata"], default={}),
                    created_at=row["created_at"],
                ))
            return findings

    async def get_all_findings(self, severity: Optional[str] = None) -> List[Finding]:
        """Get all findings, optionally filtered by severity."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            if severity:
                cursor = await db.execute(
                    "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC",
                    (severity,)
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM findings ORDER BY created_at DESC"
                )
            rows = await cursor.fetchall()
            findings = []
            for row in rows:
                findings.append(Finding(
                    session_id=row["session_id"],
                    attack_type=row["attack_type"],
                    confidence=row["confidence"],
                    endpoint=row["endpoint"],
                    parameter=row["parameter"],
                    evidence=row["evidence"],
                    status=row["status"],
                    cvss_score=row["cvss_score"],
                    severity=row["severity"],
                    remediation=row["remediation"],
                    metadata=_safe_json_loads(row["metadata"], default={}),
                    created_at=row["created_at"],
                ))
            return findings

    async def record_process(self, session_id: str, pid: int, command: str):
        """Record a running process for a session."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO running_processes (session_id, pid, command) VALUES (?, ?, ?)",
                (session_id, pid, command)
            )
            await db.commit()

    async def remove_process(self, session_id: str, pid: int):
        """Remove a process record."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "DELETE FROM running_processes WHERE session_id = ? AND pid = ?",
                (session_id, pid)
            )
            await db.commit()

    async def get_running_pids(self, session_id: str) -> List[int]:
        """Get all running PIDs for a session."""
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "SELECT pid FROM running_processes WHERE session_id = ?",
                (session_id,)
            )
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def record_ai_decision(self, session_id: str, decision_type: str, decision: dict) -> str:
        """Record an AI decision for audit trail."""
        decision_id = f"ai-{uuid.uuid4().hex[:8]}"
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO ai_decisions
                   (id, session_id, decision_type, provider, decision_json, tokens_used, input_tokens, output_tokens, latency_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id, session_id, decision_type,
                    decision.get("provider_used", "unknown"),
                    json.dumps(decision),
                    decision.get("tokens_used", 0),
                    decision.get("input_tokens", 0),
                    decision.get("output_tokens", 0),
                    decision.get("latency_ms", 0),
                )
            )
            await db.commit()
        return decision_id

    async def get_token_usage(self, session_id: str) -> Dict[str, int]:
        """Sum input/output/total tokens for a session."""
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                """SELECT COALESCE(SUM(input_tokens), 0) AS input_tokens,
                          COALESCE(SUM(output_tokens), 0) AS output_tokens,
                          COALESCE(SUM(tokens_used), 0) AS total_tokens
                   FROM ai_decisions WHERE session_id = ?""",
                (session_id,)
            )
            row = await cursor.fetchone()
            return {
                "input_tokens": row[0] or 0,
                "output_tokens": row[1] or 0,
                "total_tokens": row[2] or 0,
            }

    async def get_ai_decisions(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all AI decisions for a session."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM ai_decisions WHERE session_id = ? ORDER BY created_at",
                (session_id,)
            )
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    async def log_audit(self, session_id: str, action: str, command: str = None, result: str = None, user: str = "system"):
        """Log an audit entry."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO audit_log (session_id, action, command, result, user)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, action, command, result, user)
            )
            await db.commit()

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session and all related data (cascade delete)."""
        async with aiosqlite.connect(self._db_path) as db:
            # Delete related records first
            await db.execute("DELETE FROM findings WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM ai_decisions WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM running_processes WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM audit_log WHERE session_id = ?", (session_id,))
            # Delete session
            cursor = await db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            await db.commit()
            deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Deleted session {session_id} and all related data")
        return deleted
