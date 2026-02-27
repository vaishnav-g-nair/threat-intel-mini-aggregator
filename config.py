"""
Configuration settings for Threat Intelligence Dashboard.
Loads environment variables and provides app configuration.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration class."""

    # VirusTotal API Configuration
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    VT_BASE_URL = "https://www.virustotal.com/api/v3"

    # MalwareBazaar API Configuration
    MB_API_URL = "https://mb-api.abuse.ch/api/v1"

    # Flask Configuration
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    HOST = os.getenv("FLASK_HOST", "127.0.0.1")
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # Input Validation Patterns
    SHA256_PATTERN = r"^[a-fA-F0-9]{64}$"
    IPV4_PATTERN = r"^(\d{1,3}\.){3}\d{1,3}$"
    DOMAIN_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

    # Risk Scoring Thresholds
    RISK_HIGH_MALICIOUS = 30
    RISK_MEDIUM_SUSPICIOUS = 10
    RISK_SCORE_MALICIOUS = 3
    RISK_SCORE_FAMILY = 2
    RISK_SCORE_RANSOMWARE = 3
    RISK_SCORE_SUSPICIOUS = 1

    # Risk Level Thresholds
    RISK_LOW_MAX = 2
    RISK_MEDIUM_MAX = 5
