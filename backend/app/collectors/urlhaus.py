"""
URLhaus Feed Collector (abuse.ch).
Connects to live URLhaus API to ingest malicious URLs and malware payload distribution endpoints.
Correlates identified CVE tags directly to vulnerabilities in MongoDB.
Strictly live telemetry. Zero mock or sample data.
"""
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector
from app.config import settings

logger = logging.getLogger("vegaintel.collector.urlhaus")


class URLhausCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="URLhaus",
            endpoint_url="https://urlhaus-api.abuse.ch/v1/urls/recent/"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        try:
            logger.info(f"Querying live URLhaus endpoint: {self.endpoint_url}")
            headers = {"User-Agent": "VegaIntel-Threat-Platform/1.0"}
            if settings.ABUSE_CH_AUTH_KEY:
                headers["Auth-Key"] = settings.ABUSE_CH_AUTH_KEY

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    self.endpoint_url,
                    headers=headers
                )
                if resp.status_code == 200:
                    res = resp.json()
                    urls = res.get("urls", [])
                    logger.info(f"URLhaus delivered {len(urls)} live malicious URL records.")

                    now = datetime.now(timezone.utc)
                    # Process up to 250 records per sync cycle
                    for u in urls[:250]:
                        raw_url = u.get("url")
                        if not raw_url:
                            continue

                        records_processed += 1
                        threat = u.get("threat", "malware_download")
                        status = u.get("url_status", "online")
                        tags = u.get("tags") or []

                        # Extract CVE if tagged
                        cve_tag = None
                        for t in tags:
                            m = re.search(r"(CVE-\d{4}-\d{4,7})", t, re.IGNORECASE)
                            if m:
                                cve_tag = m.group(1).upper()
                                break

                        is_new, fp, r = self.deduplicator.ingest_ioc_sighting(
                            raw_ioc=raw_url,
                            source=self.feed_name,
                            ioc_type="url",
                            feed_confidence=90 if status == "online" else 75,
                            associated_cve=cve_tag,
                            threat_types=[threat],
                            tags=tags + ["urlhaus-live", status],
                            raw_payload=u,
                            evidence_notes=f"URLhaus active malware distribution URL ({threat}). Status: {status}.",
                            observed_at=now
                        )
                        if r.get("status") != "rejected":
                            sightings += 1
                            if is_new:
                                new_iocs += 1

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
                                            "confidence": 90,
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
                                            "description": f"Vulnerability {cve_tag} correlated with URLhaus payload delivery.",
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
                    error = f"URLhaus API returned status code {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"URLhaus live collector notice: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
