"""Tests for the server info gatherer."""
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from core.server_info import ServerInfoGatherer


@pytest.mark.asyncio
async def test_gather_normalizes_target_and_returns_info():
    pc = AsyncMock()
    pc.run = AsyncMock(return_value={
        "stdout": "Registrar: Example Registrar\nName Server: ns1.example.com\n",
        "stderr": "",
        "returncode": 0,
    })

    gatherer = ServerInfoGatherer(pc)
    info = await gatherer.gather("https://example.com/path", "sess-1")

    assert info["hostname"] == "example.com"
    assert info["target"] == "https://example.com/path"
    assert "ip" in info
    assert info["whois"].get("Registrar") == "Example Registrar"
    assert pc.run.await_count >= 3  # whois, curl, whatweb


def test_parse_whois_extracts_known_keys():
    text = "Registrar: Foo\nName Server: ns1.foo\nCreation Date: 2020-01-01\n"
    parsed = ServerInfoGatherer._parse_whois(text)
    assert parsed["Registrar"] == "Foo"
    assert parsed["Name Server"] == "ns1.foo"


def test_parse_headers_extracts_headers():
    text = "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Frame-Options: DENY\n"
    parsed = ServerInfoGatherer._parse_headers(text)
    assert parsed["Content-Type"] == "text/html"
    assert parsed["X-Frame-Options"] == "DENY"


def test_parse_whatweb_splits_plugins():
    text = "Apache[2.4], PHP[8.0], WordPress"
    parsed = ServerInfoGatherer._parse_whatweb(text)
    assert parsed == ["Apache[2.4]", "PHP[8.0]", "WordPress"]
