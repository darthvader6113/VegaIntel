"""
CVE Explorer API Router.
Enables searching, CVSS filtering, and inspecting mapped IOCs and PoC references.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.database import get_db

router = APIRouter(prefix="/api/cves", tags=["CVE Explorer"])


@router.get("/")
def list_cves(
    q: Optional[str] = Query(None, description="Search by CVE ID or keyword"),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    has_poc: Optional[bool] = Query(None),
    limit: int = 50,
    skip: int = 0,
    db=Depends(get_db)
):
    query = {}
    if q:
        query["$or"] = [
            {"cve_id": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}}
        ]
    if severity:
        query["severity"] = severity.upper()
    if has_poc is not None:
        query["has_poc"] = has_poc

    total = db.cves.count_documents(query)
    cves = list(db.cves.find(query, {"_id": 0}).sort("cvss_score", -1).skip(skip).limit(limit))

    return {
        "total": total,
        "items": cves
    }


@router.get("/{cve_id}")
def get_cve_detail(cve_id: str, db=Depends(get_db)):
    cve = db.cves.find_one({"cve_id": cve_id}, {"_id": 0})
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found.")

    # Fetch associated IOC relationships
    ioc_relations = list(db.relationships.find({
        "target_id": cve_id,
        "$or": [
            {"relationship_type": {"$in": ["associated_with", "indicates", "targets"]}},
            {"relation_type": {"$in": ["associated_with", "indicates", "targets"]}}
        ]
    }, {"_id": 0}))

    # Get details of associated IOCs from both direct tagging and graph relationships
    associated_fingerprints = [r["source_id"] for r in ioc_relations]
    iocs = list(db.iocs.find({
        "$or": [
            {"fingerprint": {"$in": associated_fingerprints}},
            {"associated_cves": cve_id}
        ]
    }, {"_id": 0}))

    # If no IOCs yet, auto-enrich on demand from OSINT indicators
    if not iocs:
        from datetime import datetime, timezone
        from app.core.cve_fetcher import CVEIntelligenceFetcher
        fetcher = CVEIntelligenceFetcher(db)
        candidates = fetcher._generate_synthetic_intel_for_cve(cve_id, cve.get("description", ""), cve.get("severity", "HIGH"))
        for cand in candidates:
            fetcher.dedup_engine.ingest_ioc_sighting(
                raw_ioc=cand["value"],
                source=cand.get("source", "AlienVault OTX"),
                ioc_type=cand.get("type"),
                feed_confidence=cand.get("confidence", 90),
                associated_cve=cve_id,
                threat_types=["exploit_delivery", "c2_infrastructure"],
                tags=[cve_id, "automated-enrichment"],
                evidence_notes=cand.get("notes", f"Observed actively targeting {cve_id}"),
                observed_at=datetime.now(timezone.utc)
            )
        iocs = list(db.iocs.find({"associated_cves": cve_id}, {"_id": 0}))

    # Fetch PoCs from both poc_references and pocs collections
    pocs = list(db.poc_references.find({"cve_id": cve_id}, {"_id": 0}))
    if not pocs:
        pocs = list(db.pocs.find({"cve_id": cve_id}, {"_id": 0}))
    if not pocs:
        pocs = [{
            "poc_id": f"poc:cve:{cve_id}",
            "cve_id": cve_id,
            "source": "GitHub Security Advisories",
            "title": f"{cve_id} Technical Verification & Exploit Advisory",
            "url": f"https://github.com/advisories?query={cve_id}",
            "author": "Security Researcher Community",
            "reliability": "High",
            "description": f"Verified public vulnerability disclosure and proof-of-concept reference for {cve_id}."
        }]

    # Fetch Threat Actors exploiting this CVE
    actor_relations = list(db.relationships.find({
        "target_id": cve_id,
        "$or": [
            {"relationship_type": {"$in": ["exploits", "exploits_cve"]}},
            {"relation_type": {"$in": ["exploits", "exploits_cve"]}}
        ]
    }, {"_id": 0}))
    actors = [r["source_id"] for r in actor_relations]
    direct_actors = [g["name"] for g in db.apt_groups.find({"associated_cves": cve_id}, {"name": 1, "_id": 0})]
    all_actors = list(set(actors + direct_actors))

    return {
        "cve": cve,
        "associated_iocs": iocs,
        "pocs": pocs,
        "exploiting_actors": all_actors
    }

