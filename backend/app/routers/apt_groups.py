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

    # If direct IOCs are still unlinked, query live threat intelligence feeds (ThreatFox) for this threat actor
    if not iocs:
        try:
            import httpx
            from app.core.deduplicator import DeduplicationEngine
            now = datetime.now(timezone.utc)
            dedup = DeduplicationEngine(db)

            # Query ThreatFox API for real threat actor indicators
            search_query = gname.lower().replace(" ", "").replace("-", "")
            with httpx.Client(timeout=3.5) as client:
                resp = client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "tag_info", "tag": search_query},
                    headers={"User-Agent": "VegaIntel-Threat-Platform/1.0"}
                )
                if resp.status_code == 200:
                    tdata = resp.json()
                    if tdata.get("query_status") == "ok":
                        for item in tdata.get("data", [])[:15]:
                            val = item.get("ioc")
                            if val:
                                dedup.ingest_ioc_sighting(
                                    raw_ioc=val,
                                    source="Abuse.ch ThreatFox API",
                                    ioc_type=item.get("ioc_type", "domain"),
                                    feed_confidence=item.get("confidence_level", 85),
                                    associated_apt=gid,
                                    threat_types=["threat_actor_infrastructure", "c2_node"],
                                    tags=[gname.lower(), "threatfox-live"],
                                    evidence_notes=f"Active threat telemetry cataloged for {gname}",
                                    observed_at=now
                                )
        except Exception:
            pass

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
