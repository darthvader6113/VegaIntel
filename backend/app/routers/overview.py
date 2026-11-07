"""
Overview API Router.
Provides platform-level intelligence metrics, deduplication efficiency stats,
feed health, and activity timelines.
"""
from fastapi import APIRouter, Depends
from app.database import get_db

router = APIRouter(prefix="/api/overview", tags=["Overview"])


@router.get("/stats")
def get_overview_stats(db=Depends(get_db)):
    total_iocs = db.iocs.count_documents({})
    total_sightings = db.sightings.count_documents({})
    total_cves = db.cves.count_documents({})
    total_apt = db.apt_groups.count_documents({})
    total_malware = db.malware.count_documents({})
    total_pocs = max(db.poc_references.count_documents({}), db.pocs.count_documents({}))

    duplicates_prevented = max(0, total_sightings - total_iocs)
    dedup_ratio = round((duplicates_prevented / total_sightings * 100), 1) if total_sightings > 0 else 0.0

    # Feed statuses
    feeds = list(db.feed_status.find({}, {"_id": 0}))

    # Distribution by IOC type
    ioc_types = list(db.iocs.aggregate([
        {"$group": {"_id": "$ioc_type", "count": {"$sum": 1}}},
        {"$project": {"type": "$_id", "count": 1, "_id": 0}},
        {"$sort": {"count": -1}}
    ]))

    # Critical severity CVEs count
    critical_cves = db.cves.count_documents({"severity": "CRITICAL"})

    # Recent sightings stream
    recent_sightings = list(db.sightings.find({}, {"_id": 0}).sort("observed_at", -1).limit(8))

    return {
        "metrics": {
            "total_canonical_iocs": total_iocs,
            "total_sightings": total_sightings,
            "duplicates_prevented": duplicates_prevented,
            "deduplication_ratio_pct": dedup_ratio,
            "monitored_cves": total_cves,
            "critical_cves": critical_cves,
            "active_threat_actors": total_apt,
            "malware_families": total_malware,
            "poc_references": total_pocs
        },
        "ioc_type_distribution": ioc_types,
        "feed_statuses": feeds,
        "recent_sightings": recent_sightings
    }

