"""
AlienVault OTX (Open Threat Exchange) Live Collector.
Connects directly to the live AlienVault OTX REST API to ingest community threat pulses,
associated IOCs (domains, IPs, hashes), and tags.
Strictly live telemetry. Zero mock or sample data.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector
from app.config import settings

logger = logging.getLogger("vegaintel.collector.otx")


class AlienVaultOTXCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="AlienVault OTX",
            endpoint_url="https://otx.alienvault.com/api/v1/pulses/subscribed"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        headers = {"User-Agent": "VegaIntel-Threat-Platform/1.0"}
        if settings.OTX_API_KEY:
            headers["X-OTX-API-KEY"] = settings.OTX_API_KEY

        try:
            logger.info(f"Querying live AlienVault OTX API at {self.endpoint_url}...")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.endpoint_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulses = data.get("results", [])
                    logger.info(f"AlienVault OTX delivered {len(pulses)} live threat pulses.")

                    for p in pulses:
                        pulse_name = p.get("name", "OTX Threat Pulse")
                        tags = p.get("tags", [])
                        for ind in p.get("indicators", []):
                            indicator_val = ind.get("indicator")
                            ind_type = ind.get("type", "domain").lower()
                            if not indicator_val:
                                continue

                            records_processed += 1
                            is_new, fp, res = self.deduplicator.ingest_ioc_sighting(
                                raw_ioc=indicator_val,
                                source=self.feed_name,
                                ioc_type=ind_type,
                                feed_confidence=80,
                                threat_types=["otx_threat_pulse"],
                                tags=tags + ["otx-live"],
                                raw_payload=ind,
                                evidence_notes=f"Reported in live AlienVault OTX pulse: {pulse_name}",
                                observed_at=datetime.now(timezone.utc)
                            )
                            if res.get("status") != "rejected":
                                sightings += 1
                                if is_new:
                                    new_iocs += 1
                else:
                    error = f"AlienVault OTX returned HTTP status {resp.status_code}"
                    logger.warning(error)

        except Exception as e:
            error = str(e)
            logger.error(f"AlienVault OTX live connection error: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
