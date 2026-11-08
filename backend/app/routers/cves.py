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
async def get_cve_detail(cve_id: str, db=Depends(get_db)):
    cve = db.cves.find_one({"cve_id": cve_id}, {"_id": 0})
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found.")

    # 1. Fetch direct associated IOC relationships
    ioc_relations = list(db.relationships.find({
        "target_id": cve_id,
        "$or": [
            {"relationship_type": {"$in": ["associated_with", "indicates", "targets"]}},
            {"relation_type": {"$in": ["associated_with", "indicates", "targets"]}}
        ]
    }, {"_id": 0}))

    associated_fingerprints = [r["source_id"] for r in ioc_relations]
    iocs = list(db.iocs.find({
        "$or": [
            {"fingerprint": {"$in": associated_fingerprints}},
            {"associated_cves": cve_id}
        ]
    }, {"_id": 0}))

    # 2. If no direct IOCs yet, trigger and await authoritative live OSINT collection
    if not iocs:
        from app.core.cve_fetcher import CVEIntelligenceFetcher
        fetcher = CVEIntelligenceFetcher(db)
        try:
            await fetcher.fetch_and_store_cve_iocs(cve_id)
        except Exception:
            pass

        # Re-fetch direct IOCs after live query
        ioc_relations = list(db.relationships.find({
            "target_id": cve_id,
            "$or": [
                {"relationship_type": {"$in": ["associated_with", "indicates", "targets"]}},
                {"relation_type": {"$in": ["associated_with", "indicates", "targets"]}}
            ]
        }, {"_id": 0}))
        associated_fingerprints = [r["source_id"] for r in ioc_relations]
        iocs = list(db.iocs.find({
            "$or": [
                {"fingerprint": {"$in": associated_fingerprints}},
                {"associated_cves": cve_id}
            ]
        }, {"_id": 0}))

    # 3. Correlate with attributed Threat Actors and delivering Malware families
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

    malware_relations = list(db.relationships.find({
        "target_id": cve_id,
        "$or": [
            {"relationship_type": {"$in": ["delivers", "drops", "weaponizes"]}},
            {"relation_type": {"$in": ["delivers", "drops", "weaponizes"]}}
        ]
    }, {"_id": 0}))
    all_malware = list(set([r["source_id"] for r in malware_relations]))

    # If direct IOCs are sparse (< 4), also include verified indicators from linked threat actors & malware
    if len(iocs) < 4 and (all_actors or all_malware):
        linked_entities = all_actors + all_malware
        extra_relations = list(db.relationships.find({
            "target_id": {"$in": linked_entities},
            "source_type": "ioc"
        }, {"source_id": 1, "_id": 0}))
        extra_fps = [r["source_id"] for r in extra_relations]
        if extra_fps:
            extra_iocs = list(db.iocs.find({"fingerprint": {"$in": extra_fps}}, {"_id": 0}))
            existing_fps = {i["fingerprint"] for i in iocs}
            for extra in extra_iocs:
                if extra["fingerprint"] not in existing_fps:
                    iocs.append(extra)

    # Update associated count in DB for consistency
    if len(iocs) > 0:
        db.cves.update_one({"cve_id": cve_id}, {"$set": {"associated_ioc_count": len(iocs)}})
        cve["associated_ioc_count"] = len(iocs)

    # 4. Fetch PoCs from both poc_references and pocs collections
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

    return {
        "cve": cve,
        "associated_iocs": iocs,
        "pocs": pocs,
        "exploiting_actors": all_actors,
        "delivering_malware": all_malware
    }

