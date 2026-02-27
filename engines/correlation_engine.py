"""
Correlation Engine.
Normalizes and merges data from multiple threat intelligence sources
into a unified response format.
"""


class CorrelationEngine:
    """
    correlating and normalizing threat Engine for intelligence data
    from multiple API sources.
    """

    @staticmethod
    def correlate(
        mb_result: dict, vt_result: dict, indicator: str, indicator_type: str
    ) -> dict:
        """
        Correlate results from MalwareBazaar and VirusTotal.

        Args:
            mb_result: Response from MalwareBazaar service
            vt_result: Response from VirusTotal service
            indicator: The original indicator value
            indicator_type: Type of indicator (hash, ip, domain)

        Returns:
            dict: Unified normalized response
        """
        mb_data = {}
        vt_data = {}

        # Extract MalwareBazaar data
        if mb_result.get("success") and mb_result.get("found"):
            mb_data = mb_result.get("data", {})

        # Extract VirusTotal data
        if vt_result.get("success") and vt_result.get("found"):
            vt_data = vt_result.get("data", {})

        # Build unified response
        correlation = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "sources": {
                "malwarebazaar": {
                    "available": mb_result.get("success", False),
                    "found": mb_result.get("found", False),
                },
                "virustotal": {
                    "available": vt_result.get("success", False),
                    "found": vt_result.get("found", False),
                    "error": vt_result.get("error")
                    if not vt_result.get("success")
                    else None,
                },
            },
            "malware_family": CorrelationEngine._extract_malware_family(mb_data),
            "tags": CorrelationEngine._extract_tags(mb_data, vt_data),
            "vt_malicious": vt_data.get("malicious_count", 0),
            "vt_suspicious": vt_data.get("suspicious_count", 0),
            "vt_harmless": vt_data.get("harmless_count", 0),
            "vt_undetected": vt_data.get("undetected_count", 0),
            "threat_label": CorrelationEngine._extract_threat_label(vt_data),
            "first_seen": CorrelationEngine._extract_first_seen(mb_data, vt_data),
            "last_analysis_date": vt_data.get("last_analysis_date", 0),
            "reputation": vt_data.get("reputation", 0),
            "raw_data": {"malwarebazaar": mb_data, "virustotal": vt_data},
        }

        return correlation

    @staticmethod
    def _extract_malware_family(mb_data: dict) -> str:
        """Extract malware family from MalwareBazaar data."""
        families = mb_data.get("malware_family", [])
        if families and isinstance(families, list):
            return families[0] if families else ""
        return str(families) if families else ""

    @staticmethod
    def _extract_tags(mb_data: dict, vt_data: dict) -> list:
        """Extract and merge tags from both sources."""
        tags = []

        # Add MalwareBazaar tags
        mb_tags = mb_data.get("tags", [])
        if isinstance(mb_tags, list):
            tags.extend(mb_tags)

        # Add VirusTotal threat labels as tags
        vt_labels = vt_data.get("threat_labels", [])
        if isinstance(vt_labels, list):
            tags.extend(vt_labels)

        # Remove duplicates while preserving order
        seen = set()
        unique_tags = []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower not in seen:
                seen.add(tag_lower)
                unique_tags.append(tag)

        return unique_tags

    @staticmethod
    def _extract_threat_label(vt_data: dict) -> str:
        """Extract threat label from VirusTotal data."""
        threat_labels = vt_data.get("threat_labels", [])
        if threat_labels and isinstance(threat_labels, list):
            return threat_labels[0]

        popular = vt_data.get("popular_threat_classification", {})
        if popular:
            suggested_threat_label = popular.get("suggested_threat_label", "")
            if suggested_threat_label:
                return suggested_threat_label

        return ""

    @staticmethod
    def _extract_first_seen(mb_data: dict, vt_data: dict) -> str:
        """Extract first seen date from available sources."""
        mb_first_seen = mb_data.get("first_seen", "")
        if mb_first_seen:
            return mb_first_seen

        vt_first = vt_data.get("first_submission_date", 0)
        if vt_first:
            from datetime import datetime

            return datetime.fromtimestamp(vt_first).isoformat()

        return ""
