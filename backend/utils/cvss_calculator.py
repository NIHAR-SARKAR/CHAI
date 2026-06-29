"""CVSS score calculator."""
from typing import Dict, Any, Optional


class CVSSCalculator:
    """Calculate CVSS v3.1 scores."""

    # CVSS v3.1 base metrics
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES = {"N": 0.85, "L": 0.62, "H": 0.27}
    UI_VALUES = {"N": 0.85, "R": 0.62}
    C_VALUES = {"H": 0.56, "L": 0.22, "N": 0}
    I_VALUES = {"H": 0.56, "L": 0.22, "N": 0}
    A_VALUES = {"H": 0.56, "L": 0.22, "N": 0}

    @staticmethod
    def calculate(
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "H",
        availability: str = "H",
    ) -> float:
        """
        Calculate CVSS v3.1 base score.

        Args:
            attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
            attack_complexity: L (Low), H (High)
            privileges_required: N (None), L (Low), H (High)
            user_interaction: N (None), R (Required)
            scope: U (Unchanged), C (Changed)
            confidentiality: H (High), L (Low), N (None)
            integrity: H (High), L (Low), N (None)
            availability: H (High), L (Low), N (None)

        Returns:
            CVSS base score (0.0 - 10.0)
        """
        av = CVSSCalculator.AV_VALUES.get(attack_vector, 0.85)
        ac = CVSSCalculator.AC_VALUES.get(attack_complexity, 0.77)
        pr = CVSSCalculator.PR_VALUES.get(privileges_required, 0.85)
        ui = CVSSCalculator.UI_VALUES.get(user_interaction, 0.85)
        c = CVSSCalculator.C_VALUES.get(confidentiality, 0.56)
        i = CVSSCalculator.I_VALUES.get(integrity, 0.56)
        a = CVSSCalculator.A_VALUES.get(availability, 0.56)

        # Impact Sub-Score
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round to one decimal place
        return round(base_score, 1)

    @staticmethod
    def severity_from_score(score: float) -> str:
        """Get severity rating from CVSS score."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        return "info"

    @staticmethod
    def from_finding(finding_type: str, endpoint_type: str = "web") -> float:
        """Estimate CVSS score from finding type."""
        # Simplified mapping for common findings
        scores = {
            "sqli": 9.8,
            "rce": 10.0,
            "cmd_injection": 9.8,
            "xss_stored": 6.1,
            "xss_reflected": 6.1,
            "auth_bypass": 8.1,
            "idor": 5.3,
            "lfi": 7.5,
            "rfi": 8.6,
            "ssrf": 8.6,
            "xxe": 7.5,
            "open_redirect": 6.1,
            "crlf_injection": 5.3,
            "directory_listing": 5.3,
            "information_disclosure": 5.3,
            "weak_ssl": 5.3,
            "missing_headers": 3.7,
            "cookie_flags": 5.3,
            "password_spray": 5.3,
            "jwt_weak": 7.5,
            "session_fixation": 6.5,
        }
        return scores.get(finding_type.lower(), 5.0)
