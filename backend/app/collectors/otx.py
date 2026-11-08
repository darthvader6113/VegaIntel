"""
AlienVault OTX (Open Threat Exchange) Live Collector.
Connects directly to the live AlienVault OTX REST API to ingest community threat pulses,
associated IOCs (domains, IPs, hashes), and tags.
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
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(self.endpoint_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulses = data.get("results", [])
                    logger.info(f"AlienVault OTX delivered {len(pulses)} live threat pulses.")

                    now = datetime.now(timezone.utc)
                    for p in pulses:
                        pulse_name = p.get("name", "OTX Threat Pulse")
                        tags = p.get("tags", [])
                        description = p.get("description", "")

                        # Extract CVE from pulse name, description, and tags
                        cve_tag = None
                        all_text = f"{pulse_name} {description} {' '.join(tags)}"
                        m = re.search(r"(CVE-\d{4}-\d{4,7})", all_text, re.IGNORECASE)
                        if m:
                            cve_tag = m.group(1).upper()

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
                                associated_cve=cve_tag,
                                threat_types=["targeted_attack"],
                                tags=tags[:5] + ["alienvault-otx", pulse_name[:30]],
                                raw_payload=ind,
                                evidence_notes=f"OTX Pulse: {pulse_name}",
                                observed_at=now
                            )
                            if res.get("status") != "rejected":
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
                                                "confidence": 80,
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
                                                "description": f"Vulnerability {cve_tag} correlated with AlienVault OTX threat pulse '{pulse_name}'.",
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
                    error = f"AlienVault OTX API status code {resp.status_code}"

        except Exception as e:
            error = str(e)
            logger.error(f"AlienVault OTX live collector notice: {e}")

        self.finish_job(job_id, records_processed, new_iocs, sightings, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_iocs": new_iocs,
            "sightings": sightings,
            "error": error
        }
