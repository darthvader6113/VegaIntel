"""
Feed Monitoring API Router.
Source health, ingestion history, freshness, and on-demand trigger.
"""
from fastapi import APIRouter, BackgroundTasks, Depends
from app.database import get_db

router = APIRouter(prefix="/api/feeds", tags=["Feed Monitoring"])


@router.get("/status")
def get_feed_statuses(db=Depends(get_db)):
    statuses = list(db.feed_status.find({}, {"_id": 0}))
    return {"feeds": statuses}


@router.get("/jobs")
def get_ingestion_jobs(limit: int = 20, db=Depends(get_db)):
    jobs = list(db.ingestion_jobs.find({}, {"_id": 0}).sort("started_at", -1).limit(limit))
    return {"total": len(jobs), "jobs": jobs}


@router.post("/sync")
async def trigger_manual_sync(background_tasks: BackgroundTasks, db=Depends(get_db)):
    from app.scheduler.orchestrator import IntelligenceOrchestrator
    orchestrator = IntelligenceOrchestrator(db)
    background_tasks.add_task(orchestrator.run_full_cycle)
    return {
        "status": "triggered",
        "message": "Manual intelligence ingestion cycle started in background."
    }

