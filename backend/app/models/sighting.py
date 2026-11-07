"""
Pydantic models for individual feed sightings.
Every sighting represents an immutable observation by an OSINT source.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field


class SightingModel(BaseModel):
    sighting_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_fingerprint: str = Field(..., description="Foreign key to canonical IOC fingerprint")
    source: str = Field(..., description="Feed source name: AlienVault OTX, ThreatFox, URLhaus, etc.")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Original raw feed record")
    feed_confidence: int = Field(default=50, ge=0, le=100)
    associated_cve: Optional[str] = None
    associated_malware: Optional[str] = None
    evidence_notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
