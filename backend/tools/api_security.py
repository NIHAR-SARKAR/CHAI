"""API-Specific Security testing tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class ApiSecurityTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "api_security"

    @property
    def description(self) -> str:
        return "API-specific security testing (mass assignment, versioning, GraphQL)"

    async def run_api_security(self, session_id: str, target: str, test_type: str = "mass_assignment", **kwargs) -> Dict[str, Any]:
        """Run API security tests."""
        if test_type == "mass_assignment":
            return await self._run_mass_assignment(session_id, target, **kwargs)
        elif test_type == "api_versioning":
            return await self._run_api_versioning(session_id, target, **kwargs)
        elif test_type == "graphql_introspection":
            return await self._run_graphql_introspection(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 8.1 – Mass Assignment
    async def _run_mass_assignment(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for mass assignment vulnerability."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        if not token:
            return {"findings": [], "raw": raw, "error": "token required for mass assignment test"}

        me_url = kwargs.get("me_url", f"{target}/api/users/me")

        # Attempt to set privileged fields
        cmd_update = (
            f"curl -s -X PUT {me_url} "
            f"-H 'Authorization: Bearer {token}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"name\":\"Test\",\"role\":\"admin\",\"isAdmin\":true,\"verified\":true,\"credits\":99999}}'"
        )
        update_result = await self._execute(cmd_update, session_id, timeout=30)
        raw["update_request"] = update_result

        # Verify if changes persisted
        cmd_verify = f"curl -s -H 'Authorization: Bearer {token}' {me_url}"
        verify_result = await self._execute(cmd_verify, session_id, timeout=30)
        raw["verify_response"] = verify_result

        if verify_result.get("returncode") == 0:
            try:
                data = json.loads(verify_result.get("stdout", "{}"))
                role = data.get("role", "")
                is_admin = data.get("isAdmin", False)
                credits = data.get("credits", 0)

                if role == "admin" or is_admin is True or credits == 99999:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="mass_assignment",
                        confidence=0.95,
                        endpoint=me_url,
                        evidence=f"Mass assignment confirmed: role={role}, isAdmin={is_admin}, credits={credits}",
                        status="confirmed",
                        cvss_score=8.1,
                        severity="high",
                        remediation="Whitelist allowed fields; ignore unexpected parameters in updates",
                    ))
                else:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="mass_assignment",
                        confidence=0.9,
                        endpoint=me_url,
                        evidence="Privileged fields correctly ignored in user update",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))
            except json.JSONDecodeError:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="mass_assignment",
                    confidence=0.5,
                    endpoint=me_url,
                    evidence="Could not parse verification response",
                    status="potential",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 8.2 – API Versioning & Old Endpoints
    async def _run_api_versioning(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Discover old or unversioned API endpoints."""
        findings = []
        raw = {}

        api_root = kwargs.get("api_root", target)
        versions = ["v1", "v2", "v3", "v0", "beta", "alpha", "old"]
        endpoints = ["/users", "/login", "/admin"]

        found_versions = []
        for version in versions:
            for ep in endpoints:
                url = f"{api_root}/api/{version}{ep}"
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
                result = await self._execute(cmd, session_id, timeout=15)
                raw[f"{version}{ep}"] = result

                if result.get("returncode") == 0:
                    code = result.get("stdout", "").strip()
                    if code != "404":
                        found_versions.append(f"/api/{version}{ep} -> HTTP {code}")

        if found_versions:
            findings.append(Finding(
                session_id=session_id,
                attack_type="old_api_version",
                confidence=0.85,
                endpoint=api_root,
                evidence=f"Old API versions accessible: {', '.join(found_versions[:10])}",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Deprecate and disable old API versions; apply same security controls",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="old_api_version",
                confidence=0.9,
                endpoint=api_root,
                evidence="No old or unversioned API endpoints discovered",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 8.3 – GraphQL Introspection
    async def _run_graphql_introspection(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test if GraphQL introspection is enabled."""
        findings = []
        raw = {}

        graphql_url = kwargs.get("graphql_url", f"{target}/graphql")
        introspection_query = '{"query":"{ __schema { types { name } } }"}'

        cmd = (
            f"curl -s -X POST {graphql_url} "
            f"-H 'Content-Type: application/json' "
            f"-d '{introspection_query}'"
        )
        result = await self._execute(cmd, session_id, timeout=30)
        raw["introspection"] = result

        if result.get("returncode") == 0:
            try:
                data = json.loads(result.get("stdout", "{}"))
                if "data" in data and "__schema" in data.get("data", {}):
                    types = data["data"]["__schema"].get("types", [])
                    type_names = [t.get("name", "") for t in types[:10]]
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="graphql_introspection",
                        confidence=0.95,
                        endpoint=graphql_url,
                        evidence=f"GraphQL introspection enabled. Sample types: {', '.join(type_names)}",
                        status="confirmed",
                        cvss_score=5.3,
                        severity="medium",
                        remediation="Disable introspection in production GraphQL APIs",
                    ))
                else:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="graphql_introspection",
                        confidence=0.9,
                        endpoint=graphql_url,
                        evidence="GraphQL introspection query rejected or disabled",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))
            except json.JSONDecodeError:
                findings.append(Finding(
                    session_id=session_id,
                    attack_type="graphql_introspection",
                    confidence=0.5,
                    endpoint=graphql_url,
                    evidence="GraphQL endpoint returned non-JSON response",
                    status="potential",
                    cvss_score=0.0,
                    severity="info",
                ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
