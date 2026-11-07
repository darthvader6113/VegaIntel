"""
Emerging Threats (Proofpoint) Live Feed Collector.
Fetches active malicious IPs, C2 servers, and brute-force hosts directly from Proofpoint rule feeds.
Endpoint: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector

logger = logging.getLogger("vegaintel.collector.emerging_threats")


class EmergingThreatsCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="Emerging Threats",
            endpoint_url="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        try:
            logger.info(f"Querying Emerging Threats live blocklist: {self.endpoint_url}")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.endpoint_url)
                if resp.status_code == 200:
                    lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                    logger.info(f"Emerging Threats delivered {len(lines)} active malicious IP indicators.")

                    for ip_candidate in lines[:30]:
                        records_processed += 1
                        is_new, fp, res = self.deduplicator.ingest_ioc_sighting(
                            raw_ioc=ip_candidate,
                            source=self.feed_name,
                            ioc_type="ip",
                            feed_confidence=92,
                            threat_types=["c2_scanning", "exploit_attempt"],
                            tags=["proofpoint-et", "compromised-host"],
                            raw_payload={"ip": ip_candidate, "feed": "et_block_ips"},
                            evidence_notes="Emerging Threats fire-rule blocked IP actively participating in adversary reconnaissance or exploit delivery.",
                            observed_at=datetime.now(timezone.utc)
                        )
                        if res.get("status") != "rejected":
                            sightings += 1
                            if is_new:
                                new_iocs += 1
                else:
                    error = f"Emerging Threats HTTP {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"Emerging Threats fetch error: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }

