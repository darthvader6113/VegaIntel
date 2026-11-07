"""
Pydantic models for Canonical IOCs and deduplication metrics.
"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class IOCModel(BaseModel):
    fingerprint: str = Field(..., description="Unique canonical fingerprint: type:normalized_value")
    ioc_type: str = Field(..., description="ip, domain, url, md5, sha1, sha256")
    ioc_value: str = Field(..., description="Normalized IOC representation")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    sighting_count: int = Field(default=1, ge=1)
    unique_sources_count: int = Field(default=1, ge=1)
    sources: List[str] = Field(default_factory=list)
    overall_confidence: int = Field(default=50, ge=0, le=100)
    threat_types: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    status: str = Field(default="active", description="active, stale, false_positive")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IOCDetailResponse(BaseModel):
    ioc: IOCModel
    sightings: List[dict] = []
    associated_cves: List[dict] = []
    associated_apt_groups: List[dict] = []
    associated_malware: List[dict] = []

