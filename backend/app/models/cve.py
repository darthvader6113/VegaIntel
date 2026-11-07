"""
Pydantic models for CVE intelligence.
"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class CVEReference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: List[str] = []


class CVEModel(BaseModel):
    cve_id: str = Field(..., description="Unique CVE identifier (e.g. CVE-2021-44228)")
    description: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cwe_ids: List[str] = []
    references: List[str] = []
    has_poc: bool = False
    associated_ioc_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class CVESummary(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    associated_ioc_count: int = 0
    has_poc: bool = False
    published_date: Optional[datetime] = None

