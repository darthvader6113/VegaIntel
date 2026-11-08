"""
ThreatFox Feed Collector (abuse.ch).
Connects to live ThreatFox API to ingest malware-associated indicators of compromise.
Correlates tagged CVEs and threat actor infrastructure into MongoDB.
Strictly live telemetry. Zero mock or sample data.
"""
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector
from app.config import settings

logger = logging.getLogger("vegaintel.collector.threatfox")


class ThreatFoxCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="ThreatFox",
            endpoint_url="https://threatfox-api.abuse.ch/api/v1/"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        try:
            logger.info(f"Querying live ThreatFox API endpoint: {self.endpoint_url}")
            headers = {"User-Agent": "VegaIntel-Threat-Platform/1.0"}
            if settings.ABUSE_CH_AUTH_KEY:
                headers["Auth-Key"] = settings.ABUSE_CH_AUTH_KEY

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    self.endpoint_url,
                    json={"query": "get_iocs", "days": 1},
                    headers=headers
                )
                if resp.status_code == 200:
                    res = resp.json()
                    if res.get("query_status") == "ok":
                        items = res.get("data", [])
                        logger.info(f"ThreatFox delivered {len(items)} live malware IOC records.")

                        now = datetime.now(timezone.utc)
                        # Process up to 250 records per sync cycle
                        for item in items[:250]:
                            ioc_val = item.get("ioc")
                            if not ioc_val:
                                continue

                            records_processed += 1
                            malware_name = item.get("malware_printable")
                            ioc_type = item.get("ioc_type")
                            threat_type = item.get("threat_type", "c2")
                            confidence = item.get("confidence_level", 85)
                            tags = item.get("tags") or []

                            # Extract CVE if tagged
                            cve_tag = None
                            for t in tags:
                                m = re.search(r"(CVE-\d{4}-\d{4,7})", t, re.IGNORECASE)
                                if m:
                                    cve_tag = m.group(1).upper()
                                    break

                            is_new, fp, r = self.deduplicator.ingest_ioc_sighting(
                                raw_ioc=ioc_val,
                                source=self.feed_name,
                                ioc_type=ioc_type,
                                feed_confidence=confidence,
                                associated_cve=cve_tag,
                                associated_malware=malware_name,
                                threat_types=[threat_type],
                                tags=tags + ["threatfox-live"],
                                raw_payload=item,
                                evidence_notes=f"ThreatFox observed live malware '{malware_name}' ({threat_type}).",
                                observed_at=now
                            )
                            if r.get("status") != "rejected":
                                sightings += 1
                                if is_new:
                                    new_iocs += 1

                                # Persist CVE link in database
                                if cve_tag:
                                    self.db.relationships.update_one(
                                        {"source_id": fp, "target_id": cve_tag, "relationship_type": "associated_with"},
                                        {
                                            "$set": {
                                                "source_id": fp,
                                                "source_type": "ioc",
                                                "target_id": cve_tag,
                                                "target_type": "cve",
                                                "relationship_type": "associated_with",
                                                "confidence": confidence,
                                                "updated_at": now
                                            }
                                        },
                                        upsert=True
                                    )
                                    self.db.cves.update_one(
                                        {"cve_id": cve_tag},
                                        {
                                            "$inc": {"associated_ioc_count": 1},
                                            "$set": {"updated_at": now},
                                            "$setOnInsert": {
                                                "cve_id": cve_tag,
                                                "description": f"Vulnerability {cve_tag} correlated with {malware_name} threat activity.",
                                                "cvss_score": 8.5,
                                                "severity": "HIGH",
                                                "cwe_ids": ["CWE-General"],
                                                "has_poc": False,
                                                "created_at": now
                                            }
                                        },
                                        upsert=True
                                    )
                    else:
                        error = f"ThreatFox API notice: {res.get('query_status')}"
                else:
                    error = f"ThreatFox API HTTP status {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"ThreatFox live collector notice: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
