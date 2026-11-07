"""
Pydantic models for threat graph relationships.
Decouples IOCs from CVEs, APT groups, malware, and PoCs.
"""
from datetime import datetime, timezone
from typing import List, Optional
import uuid
from pydantic import BaseModel, Field


class RelationshipModel(BaseModel):
    relationship_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_type: str = Field(..., description="ioc, cve, apt_group, malware, poc")
    source_id: str = Field(..., description="Unique ID / fingerprint of source")
    target_type: str = Field(..., description="cve, apt_group, malware, poc, ioc")
    target_id: str = Field(..., description="Unique ID / fingerprint of target")
    relation_type: str = Field(..., description="exploits, associated_with, uses_infrastructure, delivers, references")
    confidence: int = Field(default=75, ge=0, le=100)
    evidence_sources: List[str] = Field(default_factory=list)
    first_linked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
