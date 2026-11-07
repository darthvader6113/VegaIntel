"""
STIX 2.1 Specification compatibility schemas.
Enables standard OASIS STIX 2.1 JSON export for integration with SIEMs, SOARs, and MISP.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class STIXObject(BaseModel):
    type: str
    spec_version: str = "2.1"
    id: str
    created: str
    modified: str
    name: Optional[str] = None
    description: Optional[str] = None
    labels: List[str] = []
    confidence: Optional[int] = 50


class STIXBundle(BaseModel):
    type: str = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid.uuid4()}")
    objects: List[Dict[str, Any]] = []

