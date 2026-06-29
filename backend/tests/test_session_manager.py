"""Tests for core.session_manager — SQLite CRUD operations."""
import pytest
import pytest_asyncio
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.session_manager import SessionManager
from models.session import Finding, Session


@pytest_asyncio.fixture
async def session_mgr():
    db_path = os.path.join(tempfile.mkdtemp(), "test_sessions.db")
    mgr = SessionManager(db_path)
    await mgr.initialize()
    yield mgr


class TestSessionCRUD:
    @pytest.mark.asyncio
    async def test_create_session(self, session_mgr):
        session_id = await session_mgr.create_session(
            target="https://example.com",
            test_type="web_app",
            scope=["example.com"],
        )
        assert session_id.startswith("sess-")

    @pytest.mark.asyncio
    async def test_get_session(self, session_mgr):
        session_id = await session_mgr.create_session(
            target="https://example.com",
            test_type="web_app",
        )
        session = await session_mgr.get_session(session_id)
        assert session is not None
        assert session.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_update_session_status(self, session_mgr):
        session_id = await session_mgr.create_session(
            target="https://example.com",
            test_type="web_app",
        )
        await session_mgr.update_session_status(session_id, "running")
        session = await session_mgr.get_session(session_id)
        assert session.status == "running"

    @pytest.mark.asyncio
    async def test_update_session_metadata(self, session_mgr):
        session_id = await session_mgr.create_session(
            target="https://example.com",
            test_type="web_app",
        )
        await session_mgr.update_session_metadata(session_id, {"server_info": {"ip": "1.2.3.4"}})
        session = await session_mgr.get_session(session_id)
        assert session.metadata.get("server_info", {}).get("ip") == "1.2.3.4"


class TestFindings:
    @pytest.mark.asyncio
    async def test_add_finding(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        finding = Finding(
            session_id=session_id,
            attack_type="sqli",
            confidence=0.9,
            endpoint="/login",
            evidence="error-based sql injection",
            status="confirmed",
            cvss_score=8.5,
            severity="high",
        )
        finding_id = await session_mgr.add_finding(finding)
        assert finding_id.startswith("find-")

    @pytest.mark.asyncio
    async def test_get_findings(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        finding = Finding(
            session_id=session_id,
            attack_type="xss",
            confidence=0.8,
            endpoint="/search",
            evidence="reflected xss",
            status="confirmed",
            severity="medium",
        )
        await session_mgr.add_finding(finding)
        findings = await session_mgr.get_findings(session_id)
        assert len(findings) == 1
        assert findings[0].attack_type == "xss"

    @pytest.mark.asyncio
    async def test_get_findings_by_status(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        await session_mgr.add_finding(Finding(
            session_id=session_id,
            attack_type="info",
            confidence=1.0,
            endpoint="/",
            evidence="server banner",
            status="confirmed",
            severity="info",
        ))
        await session_mgr.add_finding(Finding(
            session_id=session_id,
            attack_type="sqli",
            confidence=0.9,
            endpoint="/login",
            evidence="error",
            status="potential",
            severity="high",
        ))
        confirmed = await session_mgr.get_findings(session_id, status="confirmed")
        assert len(confirmed) == 1


class TestAIDecisions:
    @pytest.mark.asyncio
    async def test_record_ai_decision(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        decision_id = await session_mgr.record_ai_decision(
            session_id, "plan", {"next_tool": "recon_passive", "rationale": "start with recon"}
        )
        assert decision_id.startswith("ai-")

    @pytest.mark.asyncio
    async def test_get_ai_decisions(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        await session_mgr.record_ai_decision(session_id, "plan", {"next_tool": "recon_passive"})
        await session_mgr.record_ai_decision(session_id, "evaluate", {"continue": True})
        decisions = await session_mgr.get_ai_decisions(session_id)
        assert len(decisions) == 2

    @pytest.mark.asyncio
    async def test_get_token_usage(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        await session_mgr.record_ai_decision(
            session_id, "plan",
            {"next_tool": "recon_passive", "input_tokens": 100, "output_tokens": 50, "tokens_used": 150}
        )
        await session_mgr.record_ai_decision(
            session_id, "evaluate",
            {"continue": True, "input_tokens": 80, "output_tokens": 40, "tokens_used": 120}
        )
        usage = await session_mgr.get_token_usage(session_id)
        assert usage["input_tokens"] == 180
        assert usage["output_tokens"] == 90
        assert usage["total_tokens"] == 270


class TestMigrations:
    @pytest.mark.asyncio
    async def test_adds_missing_token_columns(self):
        import sqlite3
        db_path = os.path.join(tempfile.mkdtemp(), "legacy.db")
        # Create an old-style ai_decisions table without token columns
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE ai_decisions (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                decision_type TEXT NOT NULL,
                provider TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                tokens_used INTEGER DEFAULT 0,
                latency_ms INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '2024-01-01T00:00:00.000Z'
            )
        """)
        conn.commit()
        conn.close()

        mgr = SessionManager(db_path)
        await mgr.initialize()

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("PRAGMA table_info(ai_decisions)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        assert "input_tokens" in columns
        assert "output_tokens" in columns


class TestProcessTracking:
    @pytest.mark.asyncio
    async def test_record_and_get_pids(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        await session_mgr.record_process(session_id, 1234, "nmap test.com")
        pids = await session_mgr.get_running_pids(session_id)
        assert 1234 in pids

    @pytest.mark.asyncio
    async def test_remove_process(self, session_mgr):
        session_id = await session_mgr.create_session(target="https://example.com")
        await session_mgr.record_process(session_id, 1234, "nmap test.com")
        await session_mgr.remove_process(session_id, 1234)
        pids = await session_mgr.get_running_pids(session_id)
        assert 1234 not in pids
