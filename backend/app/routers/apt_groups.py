"""
APT Groups API Router.
Threat actor profiles, infrastructure mapping, and campaign intelligence.
"""
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
    group = db.apt_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(status_code=404, detail=f"APT Group '{group_id}' not found.")

    # Mapped infrastructure (IOCs)
    infra_relations = list(db.relationships.find({
        "source_id": group_id,
        "relation_type": "uses_infrastructure"
    }, {"_id": 0}))
    infra_fingerprints = [r["target_id"] for r in infra_relations]
    iocs = list(db.iocs.find({
        "$or": [
            {"fingerprint": {"$in": infra_fingerprints}},
            {"associated_apt_groups": group_id}
        ]
    }, {"_id": 0}))

    # Targeted CVEs
    cve_relations = list(db.relationships.find({
        "source_id": group_id,
        "relation_type": "exploits_cve"
    }, {"_id": 0}))
    cve_ids = list(set([r["target_id"] for r in cve_relations] + group.get("associated_cves", [])))
    cves = list(db.cves.find({"cve_id": {"$in": cve_ids}}, {"_id": 0}))

    return {
        "group": group,
        "associated_infrastructure": iocs,
        "targeted_cves": cves
    }

