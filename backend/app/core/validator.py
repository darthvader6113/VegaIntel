"""
Evidence and IOC Validation Engine.
Filters out private IPs, RFC1918 ranges, internal domains, and verifies syntax before ingestion.
Integrates with False Positive Prevention Engine.
"""
from typing import Dict, Tuple
from app.core.false_positive import inspect_for_false_positive

# Baseline source reliability scores (0-100)
FEED_RELIABILITY_WEIGHTS: Dict[str, float] = {
    "ThreatFox": 0.90,
    "Feodo Tracker": 0.95,
    "MalwareBazaar": 0.92,
    "URLhaus": 0.88,
    "AlienVault OTX": 0.85,
    "OpenPhish": 0.92,
    "Blocklist.de": 0.90,
    "Emerging Threats": 0.93,
    "CISA KEV": 0.99,
    "NVD": 0.98,
    "MITRE ATT&CK": 0.99,
    "Manual Analyst": 1.0,
}


def validate_ioc_evidence(ioc_type: str, ioc_value: str) -> Tuple[bool, str]:
    """
    Validates if the IOC is syntactically sound and not a known benign/internal indicator.
    Returns (is_valid, reason).
    """
    if not ioc_value or len(ioc_value) < 3:
        return False, "IOC value too short or empty"

    is_fp, reason, status_code = inspect_for_false_positive(ioc_type, ioc_value)
    if is_fp:
        return False, f"False Positive Prevented: {reason}"

    return True, "Accepted"


def calculate_dynamic_confidence(
    source_name: str,
    feed_confidence: int,
    existing_confidence: int = 0,
    sighting_count: int = 1
) -> int:
    """
    Calculates overall composite confidence score based on feed reputation,
    feed-reported score, and multi-source corroboration.
    Corroboration bonus: +5 points for each additional unique source.
    """
    weight = FEED_RELIABILITY_WEIGHTS.get(source_name, 0.80)
    source_score = feed_confidence * weight

    if sighting_count <= 1 or existing_confidence == 0:
        return min(100, max(10, int(source_score)))

    # Incremental Bayesian-style boost for multi-source confirmation
    corroboration_bonus = min(20, (sighting_count - 1) * 5)
    blended = (existing_confidence * 0.7) + (source_score * 0.3) + corroboration_bonus
    return min(100, max(10, int(blended)))

