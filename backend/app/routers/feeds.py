"""
Feed Monitoring API Router.
Source health, ingestion history, freshness, cron status, and on-demand trigger.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends
from app.database import get_db
from app.config import settings

router = APIRouter(prefix="/api/feeds", tags=["Feed Monitoring"])


@router.get("/status")
def get_feed_statuses(db=Depends(get_db)):
    statuses = list(db.feed_status.find({}, {"_id": 0}))
    return {"feeds": statuses}


@router.get("/jobs")
def get_ingestion_jobs(limit: int = 20, db=Depends(get_db)):
    jobs = list(db.ingestion_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(limit))
    return {"total": len(jobs), "jobs": jobs}


@router.get("/cron")
def get_cron_scheduler_status(db=Depends(get_db)):
    """Returns cron configuration, last cycle metrics, and database scale counts."""
    from app.main import orchestrator_instance
    
    cycle_state = db.collection_state.find_one({"_id": "last_cycle_status"}, {"_id": 0}) or {}
    cve_cursor = db.collection_state.find_one({"_id": "cve_chronological_cursor"}, {"_id": 0}) or {}
    nvd_cursor = db.collection_state.find_one({"_id": "nvd_pagination_cursor"}, {"_id": 0}) or {}

    is_running = orchestrator_instance.is_running_sync if orchestrator_instance else False
    scheduler_active = orchestrator_instance.scheduler.running if orchestrator_instance and orchestrator_instance.scheduler else False

    return {
        "cron_active": scheduler_active,
        "is_syncing": is_running,
        "cron_interval_minutes": settings.CRON_COLLECTION_INTERVAL_MINUTES,
        "database_scale": {
            "total_cves": db.cves.count_documents({}),
            "total_iocs": db.iocs.count_documents({}),
            "total_sightings": db.sightings.count_documents({}),
            "total_relationships": db.relationships.count_documents({}),
            "total_apt_groups": db.apt_groups.count_documents({}),
            "total_malware": db.malware.count_documents({}),
            "total_pocs": db.poc_references.count_documents({})
        },
        "last_cycle": cycle_state,
        "cve_harvest_cursor": cve_cursor,
        "nvd_pagination_cursor": nvd_cursor
    }


@router.post("/sync")
async def trigger_manual_sync(background_tasks: BackgroundTasks, db=Depends(get_db)):
    from app.main import orchestrator_instance
    from app.scheduler.orchestrator import IntelligenceOrchestrator
    
    orch = orchestrator_instance or IntelligenceOrchestrator(db)
    background_tasks.add_task(orch.run_full_cycle)
    return {
        "status": "triggered",
        "message": "Full OSINT intelligence ingestion cycle started in background.",
        "cron_interval_minutes": settings.CRON_COLLECTION_INTERVAL_MINUTES
    }
