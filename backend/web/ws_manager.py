"""WebSocket connection manager and log broadcaster for live UI updates."""
import asyncio
import json
import logging
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import WebSocket, WebSocketDisconnect

SESSION_RE = re.compile(r"(?:session=|\[)(sess-[a-f0-9]+)(?:\]|\b)")

# Expected log format: "YYYY-MM-DD HH:MM:SS | LEVEL | source | message"
LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*(\w+)\s*\|\s*([^|]+)\|\s*(.*)$"
)


class ConnectionManager:
    """Tracks active WebSocket connections per session and broadcasts messages."""

    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self._connections.setdefault(session_id, []).append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        conns = self._connections.get(session_id, [])
        if websocket in conns:
            conns.remove(websocket)
        if not conns:
            self._connections.pop(session_id, None)

    async def broadcast(self, session_id: str, message: dict):
        """Send a JSON message to every client subscribed to a session."""
        conns = list(self._connections.get(session_id, []))
        dead = []
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)


manager = ConnectionManager()


class SessionLogStore:
    """Persist per-session console logs to NDJSON files.

    Files are stored as ``<base_dir>/<session_id>.jsonl`` and trimmed to a
    configurable maximum number of lines so they do not grow without bound.
    """

    DEFAULT_MAX_LINES = 2000
    DEFAULT_READ_LIMIT = 500

    def __init__(self, base_dir: Optional[str] = None):
        self._base_dir: Optional[Path] = Path(base_dir) if base_dir else None
        self._lock = threading.Lock()

    def set_base_dir(self, base_dir: str):
        self._base_dir = Path(base_dir)

    def _path(self, session_id: str) -> Path:
        if not self._base_dir:
            self._base_dir = Path("logs/session_logs")
        self._base_dir.mkdir(parents=True, exist_ok=True)
        return self._base_dir / f"{session_id}.jsonl"

    def append(self, session_id: str, entry: dict) -> None:
        path = self._path(session_id)
        with self._lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._trim(path)

    def read(self, session_id: str, limit: int = DEFAULT_READ_LIMIT) -> List[dict]:
        path = self._path(session_id)
        if not path.exists():
            return []
        entries: List[dict] = []
        with self._lock:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def _trim(self, path: Path, max_lines: int = DEFAULT_MAX_LINES) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > max_lines:
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(lines[-max_lines:])
        except Exception:
            pass


log_store = SessionLogStore()


def parse_log_message(message: str) -> dict:
    """Parse a CHAI-format log line into structured fields."""
    match = LOG_LINE_RE.match(message)
    if match:
        return {
            "timestamp": match[1].strip(),
            "level": match[2].strip().upper(),
            "source": match[3].strip(),
            "message": match[4].strip(),
        }
    return {"message": message}


class WebSocketLogHandler(logging.Handler):
    """Logging handler that forwards formatted log records to WebSocket clients.

    Only records containing ``session=sess-...`` are broadcast, so logs are
    scoped to their active session page in the UI. Matching logs are also
    persisted to a per-session NDJSON file so they survive page navigation.
    """

    def __init__(self, connection_manager: ConnectionManager, level: int = logging.NOTSET):
        super().__init__(level)
        self._manager = connection_manager

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            match = SESSION_RE.search(msg)
            if not match:
                return

            session_id = match.group(1)
            parsed = parse_log_message(msg)
            payload = {
                "type": "log",
                "timestamp": parsed.get("timestamp", ""),
                "level": parsed.get("level", "INFO"),
                "source": parsed.get("source", ""),
                "message": parsed.get("message", msg),
                "raw": msg,
            }

            # Persist before broadcasting so the file is always up to date
            try:
                log_store.append(session_id, payload)
            except Exception:
                # Persistence must never break logging
                self.handleError(record)

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._manager.broadcast(session_id, payload))
            except RuntimeError:
                # No event loop yet (e.g. during early startup); drop the message.
                pass
        except Exception:
            self.handleError(record)
