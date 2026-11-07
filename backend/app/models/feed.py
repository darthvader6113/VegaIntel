"""
Pydantic models for OSINT Feed health and ingestion jobs.
"""
from datetime import datetime, timezone
from typing import Optional
import uuid
from pydantic import BaseModel, Field


class FeedStatusModel(BaseModel):
    feed_name: str
    category: str = "OSINT"
    status: str = Field(default="HEALTHY", description="HEALTHY, DEGRADED, SYNCING, ERROR")
    last_successful_sync: Optional[datetime] = None
    last_error: Optional[str] = None
    total_records_ingested: int = 0
    unique_iocs_contributed: int = 0
    rate_limit_remaining: Optional[int] = 1000
    refresh_interval_minutes: int = 60
    endpoint_url: Optional[str] = None


class IngestionJobModel(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: str = Field(default="RUNNING", description="RUNNING, SUCCESS, FAILED")
    records_processed: int = 0
    new_iocs_created: int = 0
    sightings_added: int = 0
    duplicates_prevented: int = 0
    error_message: Optional[str] = None
