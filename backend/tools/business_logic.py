"""Business Logic Flaws testing tools module."""
import logging
import json
from typing import Dict, Any, List
from models.session import Finding
from tools.base import BaseTool

logger = logging.getLogger(__name__)


class BusinessLogicTools(BaseTool):
    @property
    def tool_name(self) -> str:
        return "business_logic"

    @property
    def description(self) -> str:
        return "Business logic flaw testing (negative values, coupon abuse)"

    async def run_business_logic(self, session_id: str, target: str, test_type: str = "negative_values", **kwargs) -> Dict[str, Any]:
        """Run business logic tests."""
        if test_type == "negative_values":
            return await self._run_negative_values(session_id, target, **kwargs)
        elif test_type == "coupon_abuse":
            return await self._run_coupon_abuse(session_id, target, **kwargs)
        else:
            return {"findings": [], "raw": {}, "error": f"Unknown test_type: {test_type}"}

    # Task 12.1 – Negative Values / Integer Overflow
    async def _run_negative_values(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for negative quantity and zero price acceptance."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        orders_url = kwargs.get("orders_url", f"{target}/api/orders")
        checkout_url = kwargs.get("checkout_url", f"{target}/api/checkout")

        # Negative quantity test
        cmd_neg = (
            f"curl -s -X POST {orders_url} "
            f"-H 'Authorization: Bearer {token}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"item_id\":1,\"quantity\":-1,\"price\":-99.99}}'"
        )
        result_neg = await self._execute(cmd_neg, session_id, timeout=30)
        raw["negative_order"] = result_neg

        # Zero price checkout test
        cmd_zero = (
            f"curl -s -X POST {checkout_url} "
            f"-H 'Authorization: Bearer {token}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"cart\":[{{\"id\":1,\"qty\":1,\"price\":0}}]}}'"
        )
        result_zero = await self._execute(cmd_zero, session_id, timeout=30)
        raw["zero_price_checkout"] = result_zero

        # Analyze results
        for test_name, result in [("negative_order", result_neg), ("zero_price_checkout", result_zero)]:
            if result.get("returncode") == 0:
                code = result.get("stdout", "").strip()
                # Check if it was accepted (200/201/204) vs rejected (400/422)
                if code in ["200", "201", "204"]:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="business_logic_negative_values",
                        confidence=0.9,
                        endpoint=orders_url if test_name == "negative_order" else checkout_url,
                        evidence=f"Negative/zero value accepted ({test_name}) with HTTP {code}",
                        status="confirmed",
                        cvss_score=6.5,
                        severity="medium",
                        remediation="Server-side validation: reject negative quantities and zero/negative prices",
                    ))
                elif code in ["400", "422", "403"]:
                    findings.append(Finding(
                        session_id=session_id,
                        attack_type="business_logic_negative_values",
                        confidence=0.9,
                        endpoint=orders_url if test_name == "negative_order" else checkout_url,
                        evidence=f"Negative/zero value correctly rejected ({test_name}) with HTTP {code}",
                        status="confirmed",
                        cvss_score=0.0,
                        severity="info",
                    ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}

    # Task 12.2 – Coupon/Discount Abuse
    async def _run_coupon_abuse(self, session_id: str, target: str, **kwargs) -> Dict[str, Any]:
        """Test for coupon reuse and discount abuse."""
        findings = []
        raw = {}

        token = kwargs.get("token", "")
        coupon_url = kwargs.get("coupon_url", f"{target}/api/apply-coupon")
        coupon_code = kwargs.get("coupon_code", "SAVE10")
        attempts = kwargs.get("attempts", 5)

        responses = []
        for i in range(1, attempts + 1):
            cmd = (
                f"curl -s -X POST {coupon_url} "
                f"-H 'Authorization: Bearer {token}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"code\":\"{coupon_code}\"}}'"
            )
            result = await self._execute(cmd, session_id, timeout=15)
            raw[f"attempt_{i}"] = result
            responses.append(result.get("stdout", "").strip())

        # Check if all attempts succeeded (coupon accepted every time)
        success_codes = ["200", "201", "204"]
        success_count = sum(1 for r in responses if r in success_codes)

        if success_count == attempts:
            findings.append(Finding(
                session_id=session_id,
                attack_type="coupon_abuse",
                confidence=0.95,
                endpoint=coupon_url,
                evidence=f"Coupon '{coupon_code}' accepted {success_count}/{attempts} times — no single-use enforcement",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Enforce single-use per user/account for coupons; track redemption server-side",
            ))
        elif success_count > 1:
            findings.append(Finding(
                session_id=session_id,
                attack_type="coupon_abuse",
                confidence=0.8,
                endpoint=coupon_url,
                evidence=f"Coupon '{coupon_code}' accepted {success_count}/{attempts} times — partial enforcement",
                status="confirmed",
                cvss_score=5.3,
                severity="medium",
                remediation="Enforce strict single-use per user/account for coupons",
            ))
        else:
            findings.append(Finding(
                session_id=session_id,
                attack_type="coupon_abuse",
                confidence=0.9,
                endpoint=coupon_url,
                evidence=f"Coupon correctly rejected after first use ({success_count}/{attempts} accepted)",
                status="confirmed",
                cvss_score=0.0,
                severity="info",
            ))

        return {"findings": [f.model_dump() for f in findings], "raw": raw}
