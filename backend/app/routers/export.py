"""
Export & API Router.
Provides intelligence exports in STIX 2.1 JSON, raw JSON, and CSV formats.
"""
import csv
from datetime import datetime
import io
from typing import Optional
import uuid
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse
from app.database import get_db

router = APIRouter(prefix="/api/export", tags=["Export & API"])


@router.get("/stix")
def export_stix_bundle(
    min_confidence: int = Query(50, ge=0, le=100),
    db=Depends(get_db)
):
    """
    Exports platform intelligence as an OASIS STIX 2.1 compliant bundle.
    """
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    stix_objects = []

    # 1. Export IOCs as STIX Indicators
    iocs = list(db.iocs.find({"overall_confidence": {"$gte": min_confidence}}, {"_id": 0}))
    for ioc in iocs:
        itype = ioc.get("ioc_type")
        ival = ioc.get("ioc_value")

        # Build STIX 2.1 Pattern
        pattern = f"[{itype}:value = '{ival}']"
        if itype == "domain":
            pattern = f"[domain-name:value = '{ival}']"
        elif itype == "ip":
            pattern = f"[ipv4-addr:value = '{ival}']"
        elif itype == "url":
            pattern = f"[url:value = '{ival}']"
        elif itype == "sha256":
            pattern = f"[file:hashes.'SHA-256' = '{ival}']"
        elif itype == "md5":
            pattern = f"[file:hashes.'MD5' = '{ival}']"

        indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ioc['fingerprint'])}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"IOC: {ival}",
            "description": f"Canonical IOC observed across {len(ioc.get('sources', []))} feeds ({', '.join(ioc.get('sources', []))})",
            "indicator_types": ioc.get("threat_types", ["malicious-activity"]),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": ioc.get("overall_confidence", 50),
            "labels": ioc.get("tags", [])
        })

    # 2. Export CVEs as STIX Vulnerabilities
    cves = list(db.cves.find({}, {"_id": 0}))
    for cve in cves:
        cve_stix_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, cve['cve_id'])}"
        stix_objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": cve_stix_id,
            "created": now_iso,
            "modified": now_iso,
            "name": cve["cve_id"],
            "description": cve.get("description", ""),
            "external_references": [{"source_name": "cve", "external_id": cve["cve_id"]}]
        })

    # 3. Export APT groups as STIX Intrusion Sets
    actors = list(db.apt_groups.find({}, {"_id": 0}))
    for a in actors:
        actor_stix_id = f"intrusion-set--{uuid.uuid5(uuid.NAMESPACE_DNS, a['group_id'])}"
        stix_objects.append({
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": actor_stix_id,
            "created": now_iso,
            "modified": now_iso,
            "name": a["name"],
            "aliases": a.get("aliases", []),
            "description": a.get("description", "")
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }

    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": "attachment; filename=vegaintel_threat_bundle_stix21.json"}
    )


@router.get("/csv")
def export_csv(db=Depends(get_db)):
    """
    Exports canonical deduplicated IOC repository to standard CSV format.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Fingerprint",
        "Type",
        "Value",
        "Sighting Count",
        "Unique Sources Count",
        "Sources",
        "Confidence Score",
        "Threat Types",
        "Tags",
        "First Seen",
        "Last Seen"
    ])

    iocs = db.iocs.find({}, {"_id": 0}).sort("sighting_count", -1)
    for ioc in iocs:
        writer.writerow([
            ioc.get("fingerprint"),
            ioc.get("ioc_type"),
            ioc.get("ioc_value"),
            ioc.get("sighting_count"),
            ioc.get("unique_sources_count"),
            ";".join(ioc.get("sources", [])),
            ioc.get("overall_confidence"),
            ";".join(ioc.get("threat_types", [])),
            ";".join(ioc.get("tags", [])),
            ioc.get("first_seen"),
            ioc.get("last_seen")
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vegaintel_canonical_iocs.csv"}
    )


@router.get("/json")
def export_json(db=Depends(get_db)):
    iocs = list(db.iocs.find({}, {"_id": 0}))
    return {
        "export_timestamp": datetime.utcnow().isoformat(),
        "total_canonical_records": len(iocs),
        "iocs": iocs
    }

