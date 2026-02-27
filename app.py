"""
Threat Intel Mini Aggregator - Main Flask Application.
A localhost-only web-based Threat Intelligence Dashboard.
"""

import re
from typing import Optional
from flask import Flask, render_template, request
from config import Config
from services.malwarebazaar_service import MalwareBazaarService
from services.virustotal_service import VirusTotalService
from engines.correlation_engine import CorrelationEngine
from engines.risk_engine import RiskEngine

app = Flask(__name__)
app.config.from_object(Config)


def validate_indicator(indicator: str, indicator_type: str) -> tuple:
    """
    Validate indicator based on its type.

    Args:
        indicator: The indicator value to validate
        indicator_type: Type of indicator (hash, ip, domain)

    Returns:
        tuple: (is_valid, error_message)
    """
    if not indicator or not indicator.strip():
        return False, "Indicator cannot be empty"

    indicator = indicator.strip()

    if indicator_type == "hash":
        if not re.match(Config.SHA256_PATTERN, indicator):
            return False, "Invalid SHA256 hash format (must be 64 hex characters)"

    elif indicator_type == "ip":
        if not re.match(Config.IPV4_PATTERN, indicator):
            return False, "Invalid IPv4 address format"

        # Validate octets are in range
        octets = indicator.split(".")
        for octet in octets:
            if int(octet) > 255:
                return False, "Invalid IPv4 address (octet > 255)"

    elif indicator_type == "domain":
        if not re.match(Config.DOMAIN_PATTERN, indicator):
            return False, "Invalid domain name format"
        if len(indicator) > 253:
            return False, "Domain name too long"

    return True, ""


def detect_indicator_type(indicator: str) -> Optional[str]:
    """
    Auto-detect indicator type based on format.

    Args:
        indicator: The indicator value

    Returns:
        str: Detected type (hash, ip, domain) or None
    """
    indicator = indicator.strip()

    if re.match(Config.SHA256_PATTERN, indicator):
        return "hash"
    elif re.match(Config.IPV4_PATTERN, indicator):
        return "ip"
    elif re.match(Config.DOMAIN_PATTERN, indicator):
        return "domain"

    return None


@app.route("/")
def dashboard():
    """Render the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyze an indicator using threat intelligence sources.

    Process flow:
    1. Get indicator and type from form
    2. Validate input
    3. Query MalwareBazaar (if hash)
    4. Query VirusTotal
    5. Correlate results
    6. Calculate risk score
    7. Render results
    """
    indicator = request.form.get("indicator", "").strip()
    indicator_type = request.form.get("indicator_type", "")

    # Handle auto-detection
    if indicator_type == "auto":
        detected = detect_indicator_type(indicator)
        if detected:
            indicator_type = detected
        else:
            return render_template(
                "result.html",
                error="Could not determine indicator type. Please select manually.",
            )

    # Validate input
    is_valid, error_msg = validate_indicator(indicator, indicator_type)
    if not is_valid:
        return render_template("result.html", error=error_msg)

    # Initialize services
    mb_service = MalwareBazaarService()
    vt_service = VirusTotalService()

    # Query sources based on indicator type
    mb_result = {"success": False, "found": False, "data": {}}
    vt_result = {"success": False, "found": False, "data": {}}

    try:
        # Query VirusTotal (works for all types)
        if indicator_type == "hash":
            vt_result = vt_service.query_hash(indicator)
            mb_result = mb_service.query_hash(indicator)
        elif indicator_type == "ip":
            vt_result = vt_service.query_ip(indicator)
        elif indicator_type == "domain":
            vt_result = vt_service.query_domain(indicator)

    except Exception as e:
        return render_template("result.html", error=f"Error querying APIs: {str(e)}")

    # Check if VirusTotal API key is configured
    if not Config.VT_API_KEY:
        return render_template(
            "result.html",
            error="VirusTotal API key not configured. Please add VT_API_KEY to .env file.",
        )

    # Correlate results
    correlation = CorrelationEngine.correlate(
        mb_result, vt_result, indicator, indicator_type
    )

    # Calculate risk score
    risk = RiskEngine.calculate_risk(correlation)

    # Determine if we found any data
    has_data = mb_result.get("found") or vt_result.get("found")

    return render_template(
        "result.html",
        indicator=indicator,
        indicator_type=indicator_type,
        correlation=correlation,
        risk=risk,
        has_data=has_data,
    )


@app.route("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Threat Intel Mini Aggregator"}


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
