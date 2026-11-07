"""
Unit and Integration tests for VegaIntel Deduplication Engine and APIs.
Verifies Section 3 deduplication scenario and mathematical invariants:
Unique IOCs = 2, Total Sightings = 4, Duplicates Prevented = 2.
"""
from datetime import datetime
import mongomock
import pytest
from app.core.deduplicator import DeduplicationEngine
from app.core.fingerprint import generate_fingerprint
from app.core.normalizer import defang, normalize_ioc
from app.core.validator import validate_ioc_evidence


def test_defang_and_normalize():
    # Defang URL
    raw_url = "hxxps[:]//evil-domain[.]com[/]payload[.]exe"
    clean = defang(raw_url)
    assert clean == "https://evil-domain.com/payload.exe"

    # Defang IP
    raw_ip = "194[.]38[.]20[.]41"
    clean_ip = defang(raw_ip)
    assert clean_ip == "194.38.20.41"

    # Normalize Domain
    ntype, nval = normalize_ioc("  HTTP://Oast[.]Live:80/  ", "domain")
    assert ntype == "domain"
    assert nval == "oast.live"

    # Normalize Hash
    ntype_h, nval_h = normalize_ioc("275A523C3E84193B2E3720F007F721F5B09F389481FE130F40157D814054C600")
    assert ntype_h == "sha256"
    assert nval_h == "275a523c3e84193b2e3720f007f721f5b09f389481fe130f40157d814054c600"


def test_fingerprint_generation():
    fp1 = generate_fingerprint("oast.live", "domain")
    fp2 = generate_fingerprint("  OAST.LIVE  ")
    assert fp1 == "domain:oast.live"
    assert fp2 == "domain:oast.live"
    assert fp1 == fp2


def test_validation_rejects_private_ips():
    # Private RFC1918 IP
    valid, reason = validate_ioc_evidence("ip", "192.168.1.100")
    assert not valid
    assert "RFC1918" in reason

    # Loopback IP
    valid_lb, _ = validate_ioc_evidence("ip", "127.0.0.1")
    assert not valid_lb

    # Public IP
    valid_pub, _ = validate_ioc_evidence("ip", "185.220.101.5")
    assert valid_pub


def test_section_3_deduplication_scenario():
    """
    Executes the exact scenario from Specification Section 3:
    CVE-23444 | oast.live          | OTX
    CVE-23444 | tempmicrosoft.com  | ThreatFox
    CVE-23444 | oast.live          | URLhaus
    CVE-23444 | tempmicrosoft.com  | OTX

    Expected result:
    - Total unique IOCs: 2
    - Total sightings: 4
    - Duplicate sightings: 2
    """
    mock_db = mongomock.MongoClient()["test_tip"]
    engine = DeduplicationEngine(mock_db)

    cve = "CVE-23444"

    # Sighting 1: oast.live from OTX
    is_new1, fp1, _ = engine.ingest_ioc_sighting(
        raw_ioc="oast.live",
        source="AlienVault OTX",
        associated_cve=cve,
        feed_confidence=85
    )
    assert is_new1 is True
    assert fp1 == "domain:oast.live"

    # Sighting 2: tempmicrosoft.com from ThreatFox
    is_new2, fp2, _ = engine.ingest_ioc_sighting(
        raw_ioc="tempmicrosoft.com",
        source="ThreatFox",
        associated_cve=cve,
        feed_confidence=90
    )
    assert is_new2 is True
    assert fp2 == "domain:tempmicrosoft.com"

    # Sighting 3: oast.live from URLhaus (Duplicate sighting!)
    is_new3, fp3, _ = engine.ingest_ioc_sighting(
        raw_ioc="oast.live",
        source="URLhaus",
        associated_cve=cve,
        feed_confidence=80
    )
    assert is_new3 is False
    assert fp3 == "domain:oast.live"

    # Sighting 4: tempmicrosoft.com from OTX (Duplicate sighting!)
    is_new4, fp4, _ = engine.ingest_ioc_sighting(
        raw_ioc="tempmicrosoft.com",
        source="AlienVault OTX",
        associated_cve=cve,
        feed_confidence=88
    )
    assert is_new4 is False
    assert fp4 == "domain:tempmicrosoft.com"

    # Verify counts in database
    unique_iocs = mock_db.iocs.count_documents({})
    total_sightings = mock_db.sightings.count_documents({})
    duplicates_prevented = total_sightings - unique_iocs

    assert unique_iocs == 2, f"Expected 2 unique IOCs, got {unique_iocs}"
    assert total_sightings == 4, f"Expected 4 sightings, got {total_sightings}"
    assert duplicates_prevented == 2, f"Expected 2 duplicate sightings, got {duplicates_prevented}"

    # Verify each canonical record
    oast_doc = mock_db.iocs.find_one({"fingerprint": "domain:oast.live"})
    assert oast_doc["sighting_count"] == 2
    assert set(oast_doc["sources"]) == {"AlienVault OTX", "URLhaus"}

    ms_doc = mock_db.iocs.find_one({"fingerprint": "domain:tempmicrosoft.com"})
    assert ms_doc["sighting_count"] == 2
    assert set(ms_doc["sources"]) == {"ThreatFox", "AlienVault OTX"}

    # Verify separate relationships
    rel_count = mock_db.relationships.count_documents({"target_id": cve})
    assert rel_count == 2

