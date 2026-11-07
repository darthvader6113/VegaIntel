"""
OpenPhish Live Feed Collector.
Fetches genuine active phishing and payload delivery URLs in real time.
Feed URL: https://openphish.com/feed.txt
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector

logger = logging.getLogger("vegaintel.collector.openphish")


class OpenPhishCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="OpenPhish",
            endpoint_url="https://openphish.com/feed.txt"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        try:
            logger.info(f"Querying live OpenPhish feed at {self.endpoint_url}...")
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(
                    self.endpoint_url,
                    headers={"User-Agent": "VegaIntel-Threat-Platform/1.0"}
                )
                if resp.status_code == 200:
                    lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
                    logger.info(f"OpenPhish delivered {len(lines)} real-world phishing URLs.")

                    for raw_url in lines[:30]:
                        records_processed += 1
                        is_new, fp, res = self.deduplicator.ingest_ioc_sighting(
                            raw_ioc=raw_url,
                            source=self.feed_name,
                            ioc_type="url",
                            feed_confidence=88,
                            threat_types=["credential_theft", "phishing_payload"],
                            tags=["openphish", "active-phish", "zero-day"],
                            raw_payload={"url": raw_url, "source": "openphish_live_feed"},
                            evidence_notes="Live credential harvesting / phishing payload URL identified by OpenPhish automated scanners.",
                            observed_at=datetime.now(timezone.utc)
                        )
                        if res.get("status") != "rejected":
                            sightings += 1
                            if is_new:
                                new_iocs += 1
                else:
                    error = f"OpenPhish HTTP {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"OpenPhish fetch error: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }

