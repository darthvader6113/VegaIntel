"""
APT Groups API Router.
Threat actor profiles, infrastructure mapping, and campaign intelligence.
"""
import re
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.database import get_db

router = APIRouter(prefix="/api/apt", tags=["APT Groups"])


@router.get("/")
def list_apt_groups(
    q: Optional[str] = Query(None, description="Search by name, alias or country"),
    country: Optional[str] = Query(None),
    db=Depends(get_db)
):
    query = {}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"aliases": {"$in": [q]}},
            {"origin_country": {"$regex": q, "$options": "i"}}
        ]
    if country:
        query["origin_country"] = {"$regex": country, "$options": "i"}

    groups = list(db.apt_groups.find(query, {"_id": 0}))
    return {"total": len(groups), "items": groups}


@router.get("/{group_id}")
def get_apt_group_detail(group_id: str, db=Depends(get_db)):
    group = db.apt_groups.find_one({
        "$or": [
            {"group_id": group_id},
            {"name": {"$regex": f"^{re.escape(group_id)}$", "$options": "i"}},
            {"aliases": {"$in": [group_id]}}
        ]
    }, {"_id": 0})
    if not group:
        raise HTTPException(status_code=404, detail=f"APT Group '{group_id}' not found.")

    gid = group.get("group_id", group_id)
    gname = group.get("name", group_id)

    # Mapped infrastructure (IOCs)
    infra_relations = list(db.relationships.find({
        "source_id": {"$in": [gid, gname]},
        "$or": [
            {"relationship_type": {"$in": ["uses_infrastructure", "associated_with", "c2", "uses"]}},
            {"relation_type": {"$in": ["uses_infrastructure", "associated_with", "c2", "uses"]}}
        ]
    }, {"_id": 0}))
    infra_fingerprints = [r["target_id"] for r in infra_relations]
    iocs = list(db.iocs.find({
        "$or": [
            {"fingerprint": {"$in": infra_fingerprints}},
            {"associated_apt_groups": {"$in": [gid, gname]}},
            {"ioc_value": {"$in": infra_fingerprints}}
        ]
    }, {"_id": 0}))

    if not iocs:
        malware_names = group.get("associated_malware", [])
        iocs = list(db.iocs.find({
            "$or": [
                {"associated_malware": {"$in": malware_names}},
                {"tags": {"$in": [gid.lower(), gname.lower()]}}
            ]
        }, {"_id": 0}))

    # If still empty, check ACTIVE_WILD_APTS to auto-ingest verified indicators
    if not iocs:
        from app.scheduler.orchestrator import ACTIVE_WILD_APTS
        from app.core.deduplicator import DeduplicationEngine
        now = datetime.now(timezone.utc)
        dedup = DeduplicationEngine(db)
        for actor in ACTIVE_WILD_APTS:
            if actor["group_id"].lower() == gid.lower() or actor["name"].lower() == gname.lower():
                for ind in actor.get("indicators", []):
                    dedup.ingest_ioc_sighting(
                        raw_ioc=ind["value"],
                        source="Threat Intelligence Database",
                        ioc_type=ind["type"],
                        feed_confidence=ind.get("confidence", 95),
                        associated_apt=gid,
                        threat_types=["threat_actor_infrastructure"],
                        tags=[gname.lower(), "wild-attack"],
                        evidence_notes=ind.get("notes", f"Active indicator for {gname}"),
                        observed_at=now
                    )
                break
        iocs = list(db.iocs.find({
            "$or": [
                {"associated_apt_groups": {"$in": [gid, gname]}},
                {"tags": {"$in": [gid.lower(), gname.lower()]}}
            ]
        }, {"_id": 0}))

    # Targeted CVEs
    cve_relations = list(db.relationships.find({
        "source_id": {"$in": [gid, gname]},
        "$or": [
            {"relationship_type": {"$in": ["exploits_cve", "exploits", "targets"]}},
            {"relation_type": {"$in": ["exploits_cve", "exploits", "targets"]}}
        ]
    }, {"_id": 0}))
    cve_ids = list(set([r["target_id"] for r in cve_relations] + group.get("associated_cves", [])))
    cves = list(db.cves.find({"cve_id": {"$in": cve_ids}}, {"_id": 0}))

    return {
        "group": group,
        "associated_infrastructure": iocs,
        "targeted_cves": cves
    }
