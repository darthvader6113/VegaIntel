"""
IOC Repository API Router.
Exposes deduplicated canonical IOCs, today's new detections, on-demand CVE-driven IOC discovery,
and advanced multi-parameter searching & filtering.
"""
from datetime import datetime, timedelta, timezone
import logging
import re
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.cve_fetcher import CVEIntelligenceFetcher, CVE_PATTERN
from app.core.deduplicator import DeduplicationEngine
from app.core.false_positive import inspect_for_false_positive
from app.database import get_db

logger = logging.getLogger("vegaintel.routers.iocs")

router = APIRouter(prefix="/api/iocs", tags=["IOC Repository"])


class CVEFetchRequest(BaseModel):
    cve_id: str = Field(..., description="Target CVE identifier e.g. CVE-2024-3400")


class IOCSubmissionRequest(BaseModel):
    ioc: str = Field(..., description="Indicator value or CVE ID (e.g. CVE-2024-3400 or IP/domain/hash)")
    ioc_type: Optional[str] = Field(None, description="Optional forced type: ip, domain, url, md5, sha1, sha256")
    notes: Optional[str] = "Submitted by analyst for validation and correlation"
    target_cve: Optional[str] = None
    target_malware: Optional[str] = None
    tags: List[str] = []
    feed_confidence: int = Field(default=85, ge=10, le=100)


@router.get("/")
def list_iocs(
    q: Optional[str] = Query(None, description="Search by IOC value or tag"),
    ioc_type: Optional[str] = Query(None, description="ip, domain, url, md5, sha1, sha256"),
    source: Optional[str] = Query(None, description="Filter by feed source"),
    time_range: Optional[str] = Query("all", description="today, 24h, 7d, all"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    min_sightings: Optional[int] = Query(None, ge=1),
    threat_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, description="active, false_positive"),
    limit: int = 100,
    skip: int = 0,
    db=Depends(get_db)
):
    query = {}
    if q:
        query["$or"] = [
            {"ioc_value": {"$regex": q, "$options": "i"}},
            {"tags": {"$in": [q]}},
            {"threat_types": {"$in": [q]}}
        ]
    if ioc_type:
        query["ioc_type"] = ioc_type.lower()
    if source:
        query["sources"] = {"$in": [source]}
    if min_confidence is not None:
        query["overall_confidence"] = {"$gte": min_confidence}
    if min_sightings is not None:
        query["sighting_count"] = {"$gte": min_sightings}
    if threat_type:
        query["threat_types"] = {"$in": [threat_type]}
    if status_filter:
        query["status"] = status_filter

    # Date / Time range filter ("From the day get new ioc")
    now = datetime.now(timezone.utc)
    if time_range == "today":
        start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        query["$or"] = [
            {"first_seen": {"$gte": start_of_today}},
            {"last_seen": {"$gte": start_of_today}}
        ]
    elif time_range == "24h":
        cutoff = now - timedelta(hours=24)
        query["last_seen"] = {"$gte": cutoff}
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
        query["last_seen"] = {"$gte": cutoff}

    total = db.iocs.count_documents(query)
    items = list(db.iocs.find(query, {"_id": 0}).sort("last_seen", -1).skip(skip).limit(limit))

    return {
        "total": total,
        "time_range": time_range,
        "items": items
    }


@router.get("/today")
def get_today_new_iocs(limit: int = 50, db=Depends(get_db)):
    """Convenience endpoint to retrieve indicators first observed or sighted today."""
    now = datetime.now(timezone.utc)
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    query = {
        "$or": [
            {"first_seen": {"$gte": start_of_today}},
            {"last_seen": {"$gte": start_of_today}}
        ]
    }
    total = db.iocs.count_documents(query)
    items = list(db.iocs.find(query, {"_id": 0}).sort("last_seen", -1).limit(limit))
    return {
        "date": start_of_today.strftime("%Y-%m-%d"),
        "total_new_today": total,
        "items": items
    }


@router.post("/fetch-by-cve")
async def fetch_and_store_cve_iocs_endpoint(req: CVEFetchRequest, db=Depends(get_db)):
    """
    Given a CVE identifier (e.g. CVE-2024-3400), queries NIST NVD, CISA KEV,
    ThreatFox, AlienVault OTX, and URLhaus to discover and ingest all associated network & host IOCs.
    Deduplicates indicators and persists them into the Canonical IOC Repository.
    """
    cve_id = req.cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CVE format: '{req.cve_id}'. Expected format is CVE-YYYY-NNNN (e.g. CVE-2024-3400)."
        )

    fetcher = CVEIntelligenceFetcher(db)
    try:
        result = await fetcher.fetch_and_store_cve_iocs(cve_id)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error executing CVE-driven IOC discovery for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch IOCs for {cve_id}: {str(e)}")


@router.post("/request")
async def request_and_ingest_ioc(req: IOCSubmissionRequest, db=Depends(get_db)):
    """
    On-Demand Threat Intelligence & IOC Ingestion endpoint.
    If the user provides a CVE-{number}, it triggers full CVE intelligence discovery
    and pulls in all associated indicators automatically!
    Otherwise, it validates through the False Positive Engine and ingests the single IOC.
    """
    raw = req.ioc.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Input value cannot be empty.")

    # Check if input is a CVE identifier
    if CVE_PATTERN.match(raw.upper()):
        fetcher = CVEIntelligenceFetcher(db)
        try:
            return await fetcher.fetch_and_store_cve_iocs(raw.upper())
        except Exception as e:
            logger.error(f"Error handling CVE-based request for {raw}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    engine = DeduplicationEngine(db)
    is_new, fp, res = engine.ingest_ioc_sighting(
        raw_ioc=raw,
        source="Analyst Submission",
        ioc_type=req.ioc_type,
        feed_confidence=req.feed_confidence,
        associated_cve=req.target_cve,
        associated_malware=req.target_malware,
        threat_types=["manual_submission", "threat_lead"],
        tags=req.tags + ["requested-ioc"],
        evidence_notes=req.notes or "Submitted via Analyst On-Demand Request portal.",
        observed_at=datetime.now(timezone.utc)
    )

    if res.get("status") == "rejected":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IOC rejected by False Positive Engine: {res.get('reason')}"
        )

    # Fetch updated canonical record
    canonical = db.iocs.find_one({"fingerprint": fp}, {"_id": 0})
    sightings = list(db.sightings.find({"ioc_fingerprint": fp}, {"_id": 0}))

    return {
        "status": "success",
        "fingerprint": fp,
        "is_new_canonical": is_new,
        "total_sightings": len(sightings),
        "canonical_ioc": canonical,
        "message": f"IOC successfully processed and deduplicated. Sighting count: {len(sightings)}."
    }


@router.get("/detail")
def get_ioc_detail(fingerprint: str = Query(..., description="Canonical fingerprint e.g. domain:oast.live"), db=Depends(get_db)):
    ioc = db.iocs.find_one({"fingerprint": fingerprint}, {"_id": 0})
    if not ioc:
        raise HTTPException(status_code=404, detail=f"Canonical IOC with fingerprint '{fingerprint}' not found.")

    sightings = list(db.sightings.find({"ioc_fingerprint": fingerprint}, {"_id": 0}).sort("observed_at", -1))

    cve_relations = list(db.relationships.find({"source_id": fingerprint, "target_type": "cve"}, {"_id": 0}))
    associated_cve_ids = [r["target_id"] for r in cve_relations]
    direct_cves = ioc.get("associated_cves", [])
    all_cve_ids = list(set(associated_cve_ids + direct_cves))
    cves = list(db.cves.find({"cve_id": {"$in": all_cve_ids}}, {"_id": 0}))

    malware_relations = list(db.relationships.find({"source_id": fingerprint, "target_type": "malware"}, {"_id": 0}))
    associated_malware_names = [r["target_id"] for r in malware_relations]
    direct_malware = ioc.get("associated_malware", [])
    all_malware_names = list(set(associated_malware_names + direct_malware))
    malware = list(db.malware.find({"malware_id": {"$in": all_malware_names}}, {"_id": 0}))

    apt_relations = list(db.relationships.find({"target_id": fingerprint, "source_type": "apt_group"}, {"_id": 0}))
    associated_apt_names = [r["source_id"] for r in apt_relations]
    direct_apts = ioc.get("associated_apt_groups", [])
    all_apt_ids = list(set(associated_apt_names + direct_apts))
    apt_groups = list(db.apt_groups.find({"group_id": {"$in": all_apt_ids}}, {"_id": 0}))

    return {
        "canonical_ioc": ioc,
        "sightings": sightings,
        "associated_cves": cves,
        "associated_malware": malware,
        "associated_apt_groups": apt_groups,
        "deduplication_summary": {
            "total_sightings": len(sightings),
            "unique_canonical_records": 1,
            "duplicate_sightings_merged": max(0, len(sightings) - 1),
            "sources_contributing": ioc.get("sources", [])
        }
    }
