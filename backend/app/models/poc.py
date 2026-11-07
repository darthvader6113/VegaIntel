"""
Pydantic models for PoC and Exploit references.
PoCs are handled strictly as reference metadata and never executed.
"""
from datetime import datetime, timezone
from typing import Optional
import uuid
from pydantic import BaseModel, Field


class PoCModel(BaseModel):
    poc_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: str = Field(..., description="CVE ID this PoC targets")
    source: str = Field(..., description="GitHub, Exploit-DB, Metasploit, Packet Storm")
    title: str
    url: str
    author: Optional[str] = "Anonymous"
    reliability: str = Field(default="Proof-of-Concept", description="Verified, Functional, Unverified, Proof-of-Concept")
    description: str = ""
    discovered_date: Optional[datetime] = None
    advisory: str = "TREAT AS REFERENCE ONLY. Do not execute downloaded exploit code."
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
