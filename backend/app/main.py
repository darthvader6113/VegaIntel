"""
VegaIntel Threat Intelligence Platform - FastAPI Backend Application.
Provides RESTful APIs, automated ingestion orchestration, deduplication,
threat correlation services, and serves the executive light-themed dashboard.
"""
from contextlib import asynccontextmanager
import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import db_manager
from app.routers import (
    apt_groups,
    auth,
    correlation,
    cves,
    export,
    feeds,
    iocs,
    malware,
    overview,
    pocs,
)
from app.scheduler.orchestrator import IntelligenceOrchestrator

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("vegaintel")

orchestrator_instance = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup and shutdown procedures."""
    global orchestrator_instance
    logger.info("Initializing VegaIntel backend services...")
    
    # 1. Initialize Database connection (MongoDB / mongomock)
    db_manager.connect()
    
    # 2. Initialize Ingestion Orchestrator & seed initial cycle
    orchestrator_instance = IntelligenceOrchestrator(db_manager.db)
    logger.info("Performing initial intelligence correlation cycle...")
    try:
        await orchestrator_instance.run_full_cycle()
    except Exception as e:
        logger.error(f"Initial sync warning: {e}")
        
    # 3. Start automated periodic background collection scheduler
    orchestrator_instance.setup_scheduler()
    
    logger.info("VegaIntel Threat Intelligence Platform is ready!")
    yield
    
    # Shutdown
    logger.info("Shutting down VegaIntel services...")
    if orchestrator_instance and orchestrator_instance.scheduler.running:
        orchestrator_instance.scheduler.shutdown()
    db_manager.close()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Centralized, automated Threat Intelligence Platform deduplicating OSINT feeds, correlating CVEs, APT groups, malware, and exploit PoCs.",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(overview.router)
app.include_router(cves.router)
app.include_router(iocs.router)
app.include_router(apt_groups.router)
app.include_router(malware.router)
app.include_router(pocs.router)
app.include_router(feeds.router)
app.include_router(export.router)
app.include_router(correlation.router)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "HEALTHY",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database_mode": "mock_fallback" if db_manager.is_mock_db else "production_mongo",
        "redis_mode": "mock_fallback" if db_manager.is_mock_redis else "production_redis"
    }


# Mount production frontend static build if compiled
dist_candidates = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "frontend", "dist"),
    os.path.join(os.getcwd(), "frontend", "dist")
]
for dist_path in dist_candidates:
    norm_path = os.path.normpath(dist_path)
    if os.path.exists(norm_path) and os.path.exists(os.path.join(norm_path, "index.html")):
        logger.info(f"Mounting frontend dashboard from {norm_path} at /")
        app.mount("/", StaticFiles(directory=norm_path, html=True), name="frontend")
        break


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
