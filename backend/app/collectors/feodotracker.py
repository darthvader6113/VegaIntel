"""
Feodo Tracker Live Feed Collector (abuse.ch).
Fetches genuine real-world Botnet Command & Control (C2) servers in real time.
Strictly live OSINT telemetry.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector

logger = logging.getLogger("vegaintel.collector.feodotracker")


class FeodoTrackerCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="Feodo Tracker",
            endpoint_url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_iocs = 0
        sightings = 0
        error = None

        try:
            logger.info(f"Querying live Feodo Tracker OSINT endpoint: {self.endpoint_url}")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.endpoint_url)
                if resp.status_code == 200:
                    entries = resp.json()
                    logger.info(f"Feodo Tracker delivered {len(entries)} real live C2 indicators.")

                    for item in entries[:50]:
                        records_processed += 1
                        ip_addr = item.get("ip_address")
                        if not ip_addr:
                            continue

                        port = item.get("port", 443)
                        malware = item.get("malware", "Unknown Botnet")
                        c2_status = item.get("c2_status", "online")
                        first_seen_str = item.get("first_seen_utc")

                        observed_time = datetime.now(timezone.utc)
                        if first_seen_str:
                            try:
                                observed_time = datetime.fromisoformat(first_seen_str.replace(" ", "T"))
                            except Exception:
                                pass

                        is_new, fp, _ = self.deduplicator.ingest_ioc_sighting(
                            raw_ioc=ip_addr,
                            source=self.feed_name,
                            ioc_type="ip",
                            feed_confidence=95 if c2_status == "online" else 80,
                            associated_malware=malware,
                            threat_types=["botnet_c2", "c2_infrastructure"],
                            tags=["feodo-tracker", malware.lower(), f"port-{port}", c2_status],
                            raw_payload=item,
                            evidence_notes=f"Active C2 botnet verified by abuse.ch Feodo Tracker on port {port}. Status: {c2_status}.",
                            observed_at=observed_time
                        )
                        sightings += 1
                        if is_new:
                            new_iocs += 1
                else:
                    error = f"Feodo Tracker HTTP {resp.status_code}"
                    logger.warning(error)

        except Exception as e:
            error = str(e)
            logger.error(f"Feodo Tracker live collection error: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
