"""
Risk Scoring Engine.
Calculates threat risk scores based on multiple indicators
from threat intelligence sources.
"""

from config import Config


class RiskEngine:
    """
    Engine for calculating risk scores based on threat intelligence data.
    Uses multiple weighted factors to determine overall threat level.
    """

    @staticmethod
    def calculate_risk(correlation_data: dict) -> dict:
        """
        Calculate risk score and level based on correlated data.

        Args:
            correlation_data: Normalized data from CorrelationEngine

        Returns:
            dict: Risk score and level
        """
        score = 0
        factors = []

        # Factor 1: High malicious count from VirusTotal
        malicious = correlation_data.get("vt_malicious", 0)
        if malicious > Config.RISK_HIGH_MALICIOUS:
            score += Config.RISK_SCORE_MALICIOUS
            factors.append(
                {
                    "factor": "High VirusTotal malicious detections",
                    "value": malicious,
                    "points": Config.RISK_SCORE_MALICIOUS,
                }
            )

        # Factor 2: Malware family identified
        malware_family = correlation_data.get("malware_family", "")
        if malware_family:
            score += Config.RISK_SCORE_FAMILY
            factors.append(
                {
                    "factor": "Malware family identified",
                    "value": malware_family,
                    "points": Config.RISK_SCORE_FAMILY,
                }
            )

        # Factor 3: Ransomware tag
        tags = correlation_data.get("tags", [])
        ransomware_keywords = ["ransomware", "ransom", "locker", "cryptolocker"]

        has_ransomware_tag = any(
            any(keyword in tag.lower() for keyword in ransomware_keywords)
            for tag in tags
        )

        if has_ransomware_tag:
            score += Config.RISK_SCORE_RANSOMWARE
            factors.append(
                {
                    "factor": "Ransomware tag detected",
                    "value": "Yes",
                    "points": Config.RISK_SCORE_RANSOMWARE,
                }
            )

        # Factor 4: Suspicious detections
        suspicious = correlation_data.get("vt_suspicious", 0)
        if suspicious > Config.RISK_MEDIUM_SUSPICIOUS:
            score += Config.RISK_SCORE_SUSPICIOUS
            factors.append(
                {
                    "factor": "Suspicious detections",
                    "value": suspicious,
                    "points": Config.RISK_SCORE_SUSPICIOUS,
                }
            )

        # Determine risk level based on score
        risk_level = RiskEngine._get_risk_level(score)

        return {
            "score": score,
            "risk_level": risk_level,
            "factors": factors,
            "summary": RiskEngine._generate_summary(score, risk_level, factors),
        }

    @staticmethod
    def _get_risk_level(score: int) -> str:
        """
        Determine risk level from score.

        Args:
            score: Calculated risk score

        Returns:
            str: Risk level (LOW, MEDIUM, HIGH)
        """
        if score <= Config.RISK_LOW_MAX:
            return "LOW"
        elif score <= Config.RISK_MEDIUM_MAX:
            return "MEDIUM"
        else:
            return "HIGH"

    @staticmethod
    def _generate_summary(score: int, risk_level: str, factors: list) -> str:
        """
        Generate human-readable summary of risk assessment.

        Args:
            score: Calculated risk score
            risk_level: Risk level
            factors: List of contributing factors

        Returns:
            str: Summary text
        """
        if not factors:
            return "No threat indicators found. This indicator appears clean."

        factor_summary = ", ".join([f["factor"] for f in factors])

        if risk_level == "HIGH":
            return f"HIGH RISK: {len(factors)} threat indicators detected ({factor_summary}). Immediate investigation recommended."
        elif risk_level == "MEDIUM":
            return f"MEDIUM RISK: {len(factors)} indicators require attention ({factor_summary}). Review recommended."
        else:
            return f"LOW RISK: Minor indicators detected ({factor_summary}). Monitor if needed."
