"""Lightweight server/network reconnaissance for the session overview."""
import re
import socket
import ssl
import urllib.request
from typing import Dict, Any, List
from urllib.parse import urlparse


class ServerInfoGatherer:
    """Gather basic server details (WHOIS, DNS, headers, tech, SSL) for a target."""

    def __init__(self, process_controller):
        self._process = process_controller

    @staticmethod
    def normalize_hostname(target: str) -> str:
        """Strip scheme/path/port and return a bare hostname."""
        if not target:
            return ""
        t = target.strip()
        if "://" not in t:
            t = "http://" + t
        parsed = urlparse(t)
        host = parsed.hostname or t
        return host.lower()

    async def gather(self, target: str, session_id: str) -> Dict[str, Any]:
        """Run a short recon pass and return structured server info."""
        hostname = self.normalize_hostname(target)
        info: Dict[str, Any] = {"target": target, "hostname": hostname}

        if not hostname:
            info["error"] = "Could not parse hostname"
            return info

        # DNS resolution
        info["dns"] = self._resolve_dns(hostname)
        info["ip"] = info["dns"].get("ipv4", ["-"])[0]

        # WHOIS
        whois_raw = await self._run_cmd(f"whois {hostname}", session_id, timeout=30)
        info["whois_raw"] = whois_raw
        info["whois"] = self._parse_whois(whois_raw)

        # HTTP headers
        headers_raw = await self._run_cmd(
            f"curl -I -L -s --max-time 10 http://{hostname}", session_id, timeout=15
        )
        if not headers_raw:
            # Fallback to Python urllib for headers
            headers_raw = self._fetch_headers_with_urllib(hostname)
        info["headers_raw"] = headers_raw
        info["headers"] = self._parse_headers(headers_raw)

        # SSL certificate (HTTPS)
        info["ssl"] = self._get_ssl_info(hostname)

        # Technology fingerprinting
        tech_raw = await self._run_cmd(
            f"whatweb -a 1 -q http://{hostname}", session_id, timeout=30
        )
        info["technologies"] = self._parse_whatweb(tech_raw)

        # Extract useful single fields
        info["server_header"] = info["headers"].get("Server") or info["headers"].get("server") or "-"
        info["powered_by"] = info["headers"].get("X-Powered-By") or info["headers"].get("x-powered-by") or "-"

        return info

    async def _run_cmd(self, command: str, session_id: str, timeout: int) -> str:
        result = await self._process.run(
            command=command,
            session_id=session_id,
            timeout=timeout,
            sandbox_level="none",
        )
        if result.get("returncode") == 0:
            return result.get("stdout", "")
        return ""

    @staticmethod
    def _resolve_dns(hostname: str) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {"ipv4": [], "ipv6": [], "aliases": []}
        try:
            _, aliases, ips = socket.gethostbyname_ex(hostname)
            result["ipv4"] = ips
            result["aliases"] = aliases
        except Exception:
            pass
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in result["ipv4"]:
                    result["ipv4"].append(ip)
                elif family == socket.AF_INET6 and ip not in result["ipv6"]:
                    result["ipv6"].append(ip)
        except Exception:
            pass
        return result

    @staticmethod
    def _fetch_headers_with_urllib(hostname: str) -> str:
        """Fallback header fetch using stdlib."""
        try:
            req = urllib.request.Request(f"http://{hostname}", method="HEAD")
            req.add_header("User-Agent", "CHAI-Recon/1.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                lines = [f"HTTP/1.1 {resp.getcode()}"]
                for key, value in resp.headers.items():
                    lines.append(f"{key}: {value}")
                return "\n".join(lines)
        except Exception:
            return ""

    @staticmethod
    def _get_ssl_info(hostname: str) -> Dict[str, Any]:
        """Fetch SSL certificate info for the hostname."""
        info: Dict[str, Any] = {"has_ssl": False}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    info["has_ssl"] = True
                    info["subject"] = cert.get("subject")
                    info["issuer"] = cert.get("issuer")
                    info["not_after"] = cert.get("notAfter")
                    info["serial_number"] = cert.get("serialNumber")
                    cipher = ssock.cipher()
                    info["cipher"] = cipher[0] if cipher else None
        except Exception as e:
            info["error"] = str(e)
        return info

    @staticmethod
    def _parse_whois(text: str) -> Dict[str, Any]:
        if not text:
            return {}
        keys = ["Registrar", "Registrant", "Name Server", "Creation Date", "Expiration Date", "Domain Status"]
        parsed = {}
        for line in text.splitlines():
            for key in keys:
                if line.lower().startswith(key.lower() + ":"):
                    value = line.split(":", 1)[1].strip()
                    if key not in parsed:
                        parsed[key] = value
        return parsed

    @staticmethod
    def _parse_headers(text: str) -> Dict[str, str]:
        headers = {}
        for line in text.splitlines():
            if ":" in line and not line.lower().startswith("http/"):
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    @staticmethod
    def _parse_whatweb(text: str) -> list[str]:
        if not text:
            return []
        parts = [p.strip() for p in text.split(",") if p.strip()]
        return parts[:20]
