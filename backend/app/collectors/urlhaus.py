"""
URLhaus Feed Collector (abuse.ch).
Connects to live URLhaus API to ingest malicious URLs and malware payload distribution endpoints.
Strictly live telemetry. Zero mock or sample data.
"""
from datetime import datetime, timezone
import logging
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

            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    self.endpoint_url,
                    headers=headers
                )
                if resp.status_code == 200:
                    res = resp.json()
                    urls = res.get("urls", [])
                    logger.info(f"URLhaus delivered {len(urls)} live malicious URL records.")

                    for u in urls[:50]:
                        raw_url = u.get("url")
                        if not raw_url:
                            continue

                        records_processed += 1
                        threat = u.get("threat", "malware_download")
                        status = u.get("url_status", "online")
                        tags = u.get("tags") or []

                        is_new, fp, r = self.deduplicator.ingest_ioc_sighting(
                            raw_ioc=raw_url,
                            source=self.feed_name,
                            ioc_type="url",
                            feed_confidence=88 if status == "online" else 75,
                            threat_types=[threat],
                            tags=tags + ["urlhaus-live"],
                            raw_payload=u,
                            evidence_notes=f"URLhaus live tracked payload distribution server: status={status}, threat={threat}.",
                            observed_at=datetime.now(timezone.utc)
                        )
                        if r.get("status") != "rejected":
                            sightings += 1
                            if is_new:
                                new_iocs += 1
                else:
                    error = f"URLhaus API HTTP status {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"URLhaus live collection notice: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
