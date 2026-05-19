"""SQLite session CRUD + state machine with AI decision logging."""
import aiosqlite
import uuid
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from models.session import Session, Finding

logger = logging.getLogger(__name__)


class SessionManager:
    def __init__(self, db_path: str):
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self):
        """Initialize database with schema."""
        init_sql_path = Path(__file__).parent.parent / "data" / "init_sessions.sql"
        async with aiosqlite.connect(self._db_path) as db:
            with open(init_sql_path, "r") as f:
                await db.executescript(f.read())
            await db.commit()
        logger.info("Session database initialized")

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
                    scope=json.loads(row["scope"]),
                    status=row["status"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    findings_count=row["findings_count"],
                    metadata=json.loads(row["metadata"]),
                )
            return None

    async def update_session_status(self, session_id: str, status: str):
        """Update session status."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE sessions SET status = ? WHERE session_id = ?",
                (status, session_id)
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
                    metadata=json.loads(row["metadata"]),
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
                   (id, session_id, decision_type, provider, decision_json, tokens_used, latency_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id, session_id, decision_type,
                    decision.get("provider_used", "unknown"),
                    json.dumps(decision),
                    decision.get("tokens_used", 0),
                    decision.get("latency_ms", 0),
                )
            )
            await db.commit()
        return decision_id

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
