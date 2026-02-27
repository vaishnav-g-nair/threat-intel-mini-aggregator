"""
VirusTotal API Service (v3).
Provides functionality to query files, IP addresses, and domains.
"""

import requests
from config import Config


class VirusTotalService:
    """
    Service class for interacting with VirusTotal API v3.
    Supports querying files, IP addresses, and domains.
    """

    def __init__(self):
        """Initialize the service with API key and base URL."""
        self.api_key = Config.VT_API_KEY
        self.base_url = Config.VT_BASE_URL
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    def query_hash(self, sha256: str) -> dict:
        """
        Query VirusTotal for information about a file hash.

        Args:
            sha256: SHA256 hash of the file to query

        Returns:
            dict: Normalized response with file analysis data
        """
        endpoint = f"{self.base_url}/files/{sha256}"
        return self._make_request(endpoint, "file")

    def query_ip(self, ip_address: str) -> dict:
        """
        Query VirusTotal for information about an IP address.

        Args:
            ip_address: IPv4 address to query

        Returns:
            dict: Normalized response with IP analysis data
        """
        endpoint = f"{self.base_url}/ip_addresses/{ip_address}"
        return self._make_request(endpoint, "ip")

    def query_domain(self, domain: str) -> dict:
        """
        Query VirusTotal for information about a domain.

        Args:
            domain: Domain name to query

        Returns:
            dict: Normalized response with domain analysis data
        """
        endpoint = f"{self.base_url}/domains/{domain}"
        return self._make_request(endpoint, "domain")

    def _make_request(self, endpoint: str, indicator_type: str) -> dict:
        """
        Make API request to VirusTotal and normalize response.

        Args:
            endpoint: Full API endpoint URL
            indicator_type: Type of indicator (file, ip, domain)

        Returns:
            dict: Normalized response data
        """
        if not self.api_key:
            return {"success": False, "error": "VirusTotal API key not configured"}

        try:
            response = requests.get(endpoint, headers=self.headers, timeout=30)

            if response.status_code == 404:
                return {"success": True, "found": False, "data": {}}

            if response.status_code == 429:
                return {
                    "success": False,
                    "error": "Rate limit exceeded - please wait and try again",
                }

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                }

            data = response.json()
            return self._normalize_response(data, indicator_type)

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timeout - API may be unavailable",
            }
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}

    def _normalize_response(self, raw_data: dict, indicator_type: str) -> dict:
        """
        Normalize VirusTotal response to consistent format.

        Args:
            raw_data: Raw API response data
            indicator_type: Type of indicator (file, ip, domain)

        Returns:
            dict: Normalized threat intelligence data
        """
        if indicator_type == "file":
            return self._normalize_file_data(raw_data)
        elif indicator_type == "ip":
            return self._normalize_ip_data(raw_data)
        elif indicator_type == "domain":
            return self._normalize_domain_data(raw_data)

        return {"success": False, "error": "Unknown indicator type"}

    def _normalize_file_data(self, data: dict) -> dict:
        """Normalize file analysis response."""
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis = attributes.get("last_analysis_stats", {})
        last_analysis_date = attributes.get("last_analysis_date", 0)

        return {
            "success": True,
            "found": True,
            "data": {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "harmless_count": last_analysis.get("harmless", 0),
                "undetected_count": last_analysis.get("undetected", 0),
                "last_analysis_date": last_analysis_date,
                "reputation": attributes.get("reputation", 0),
                "meaningful_name": attributes.get("meaningful_name", ""),
                "type_description": attributes.get("type_description", ""),
                "names": attributes.get("names", []),
                "threat_labels": attributes.get("threat_labels", []),
                "popular_threat_classification": attributes.get(
                    "popular_threat_classification", {}
                ),
                "last_submission_date": attributes.get("last_submission_date", 0),
                "first_submission_date": attributes.get("first_submission_date", 0),
            },
        }

    def _normalize_ip_data(self, data: dict) -> dict:
        """Normalize IP address analysis response."""
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis = attributes.get("last_analysis_stats", {})
        last_analysis_date = attributes.get("last_analysis_date", 0)

        return {
            "success": True,
            "found": True,
            "data": {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "harmless_count": last_analysis.get("harmless", 0),
                "undetected_count": last_analysis.get("undetected", 0),
                "last_analysis_date": last_analysis_date,
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country", ""),
                "as_owner": attributes.get("as_owner", ""),
                "network": attributes.get("network", ""),
                "threat_labels": attributes.get("threat_labels", []),
                "last_modification_date": attributes.get("last_modification_date", 0),
            },
        }

    def _normalize_domain_data(self, data: dict) -> dict:
        """Normalize domain analysis response."""
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis = attributes.get("last_analysis_stats", {})
        last_analysis_date = attributes.get("last_analysis_date", 0)

        return {
            "success": True,
            "found": True,
            "data": {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "harmless_count": last_analysis.get("harmless", 0),
                "undetected_count": last_analysis.get("undetected", 0),
                "last_analysis_date": last_analysis_date,
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country", ""),
                "registrar": attributes.get("registrar", ""),
                "creation_date": attributes.get("creation_date", 0),
                "last_modification_date": attributes.get("last_modification_date", 0),
                "threat_labels": attributes.get("threat_labels", []),
                "last_dns_records": attributes.get("last_dns_records", []),
                "dns_records": attributes.get("dns_records", {}),
            },
        }
