"""
Pydantic models for APT groups (MITRE ATT&CK threat actors).
"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class APTGroupModel(BaseModel):
    group_id: str = Field(..., description="Unique ID / Name (e.g. APT29, Lazarus Group)")
    name: str
    aliases: List[str] = []
    origin_country: Optional[str] = None
    description: str = ""
    target_sectors: List[str] = []
    techniques: List[str] = []
    associated_malware: List[str] = []
    associated_cves: List[str] = []
    infrastructure_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

