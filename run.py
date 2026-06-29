#!/usr/bin/env python3
"""CHAI launcher — sets PYTHONPATH and runs the backend MCP + Web UI server."""
import sys
from pathlib import Path

# Ensure backend/ is on PYTHONPATH so all absolute imports resolve
backend_dir = Path(__file__).parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from backend.main import main  # noqa: E402
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
