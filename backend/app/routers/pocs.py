"""
PoC Library API Router.
Exploit references, repositories, and vulnerability links.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from app.database import get_db

router = APIRouter(prefix="/api/pocs", tags=["PoC Library"])


@router.get("/")
def list_pocs(
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    source: Optional[str] = Query(None, description="GitHub, Exploit-DB, Metasploit"),
    reliability: Optional[str] = Query(None),
    db=Depends(get_db)
):
    query = {}
    if cve_id:
        query["cve_id"] = {"$regex": cve_id, "$options": "i"}
    if source:
        query["source"] = {"$regex": source, "$options": "i"}
    if reliability:
        query["reliability"] = reliability

    pocs = list(db.poc_references.find(query, {"_id": 0}).sort("created_at", -1))
    return {
        "advisory": "TREAT AS REFERENCE ONLY. Never automatically execute downloaded exploit code.",
        "total": len(pocs),
        "items": pocs
    }

