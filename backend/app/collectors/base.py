"""
Base Collector Interface for OSINT intelligence feeds.
Handles job execution tracking, rate limiting, error catching, and metrics.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from app.core.deduplicator import DeduplicationEngine

logger = logging.getLogger("vegaintel.collector")


class BaseCollector(ABC):
    def __init__(self, db, feed_name: str, endpoint_url: Optional[str] = None):
        self.db = db
        self.feed_name = feed_name
        self.endpoint_url = endpoint_url
        self.deduplicator = DeduplicationEngine(db)

    @abstractmethod
    async def fetch_and_process(self) -> Dict[str, Any]:
        """Fetch raw records from the feed and ingest via DeduplicationEngine."""
        pass

    def start_job(self) -> str:
        """Creates an ingestion job record in MongoDB."""
        job_id = str(uuid.uuid4())
        job_doc = {
            "job_id": job_id,
            "source": self.feed_name,
            "started_at": datetime.now(timezone.utc),
            "completed_at": None,
            "status": "RUNNING",
            "records_processed": 0,
            "new_iocs_created": 0,
            "sightings_added": 0,
            "duplicates_prevented": 0,
            "error_message": None
        }
        self.db.ingestion_jobs.insert_one(job_doc)
        self.db.feed_status.update_one(
            {"feed_name": self.feed_name},
            {"$set": {"status": "SYNCING", "endpoint_url": self.endpoint_url}},
            upsert=True
        )
        return job_id

    def finish_job(
        self,
        job_id: str,
        records_processed: int,
        new_iocs: int,
        sightings: int,
        error: Optional[str] = None
    ):
        """Updates job and feed status in MongoDB."""
        status = "FAILED" if error else "SUCCESS"
        duplicates_prevented = max(0, sightings - new_iocs)
        now = datetime.now(timezone.utc)

        self.db.ingestion_jobs.update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "completed_at": now,
                    "status": status,
                    "records_processed": records_processed,
                    "new_iocs_created": new_iocs,
                    "sightings_added": sightings,
                    "duplicates_prevented": duplicates_prevented,
                    "error_message": error
                }
            }
        )

        feed_update: Dict[str, Any] = {
            "status": "ERROR" if error else "HEALTHY",
            "last_error": error,
        }
        if not error:
            feed_update["last_successful_sync"] = now
            self.db.feed_status.update_one(
                {"feed_name": self.feed_name},
                {
                    "$set": feed_update,
                    "$inc": {
                        "total_records_ingested": sightings,
                        "unique_iocs_contributed": new_iocs
                    }
                },
                upsert=True
            )
        else:
            self.db.feed_status.update_one(
                {"feed_name": self.feed_name},
                {"$set": feed_update},
                upsert=True
            )
        logger.info(f"[{self.feed_name}] Job {job_id} finished: {status}. Sightings: {sightings}, New IOCs: {new_iocs}, Duplicates Prevented: {duplicates_prevented}")

