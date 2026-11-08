"""
APT Groups API Router.
Threat actor profiles, infrastructure mapping, and campaign intelligence.
"""
import re
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
            {"associated_apt_groups": {"$in": [gid, gname]}}
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

