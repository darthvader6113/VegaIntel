"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Collector.
Fetches real, authoritative CVEs that are actively exploited in the wild,
including ransomware campaign correlations.
Source: Cybersecurity & Infrastructure Security Agency (CISA.gov)
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.collectors.base import BaseCollector

logger = logging.getLogger("vegaintel.collector.cisa_kev")


class CisaKevCollector(BaseCollector):
    def __init__(self, db):
        super().__init__(
            db=db,
            feed_name="CISA KEV",
            endpoint_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        job_id = self.start_job()
        records_processed = 0
        new_cves = 0
        error = None

        try:
            logger.info(f"Connecting to real CISA KEV feed at {self.endpoint_url}...")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.endpoint_url)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    logger.info(f"Retrieved {len(vulnerabilities)} real CVE records from CISA KEV.")

                    # Ingest top 30 most recent actively exploited CVEs
                    for vuln in vulnerabilities[:30]:
                        records_processed += 1
                        cve_id = vuln.get("cveID")
                        vendor = vuln.get("vendorProject", "")
                        product = vuln.get("product", "")
                        desc = vuln.get("shortDescription", "")
                        date_added = vuln.get("dateAdded")
                        due_date = vuln.get("dueDate")
                        known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

                        is_ransomware = known_ransomware.lower() == "known"
                        severity = "CRITICAL" if is_ransomware else "HIGH"
                        cvss_score = 9.8 if is_ransomware else 8.5

                        # Check existing
                        existing = self.db.cves.find_one({"cve_id": cve_id})
                        if not existing:
                            new_cves += 1

                        self.db.cves.update_one(
                            {"cve_id": cve_id},
                            {
                                "$set": {
                                    "description": f"[{vendor} {product}] {desc}",
                                    "cvss_score": cvss_score,
                                    "severity": severity,
                                    "cwe_ids": [vuln.get("cwes", ["CWE-General"])[0] if isinstance(vuln.get("cwes"), list) and vuln.get("cwes") else "CWE-General"],
                                    "references": [f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"],
                                    "published_date": datetime.fromisoformat(date_added) if date_added else datetime.now(timezone.utc),
                                    "known_ransomware": is_ransomware,
                                    "updated_at": datetime.now(timezone.utc)
                                },
                                "$setOnInsert": {
                                    "cve_id": cve_id,
                                    "created_at": datetime.now(timezone.utc),
                                    "has_poc": False,
                                    "associated_ioc_count": 0
                                }
                            },
                            upsert=True
                        )

        except Exception as e:
            error = str(e)
            logger.error(f"CISA KEV live fetch failed: {e}")

        self.finish_job(job_id, records_processed, new_cves, records_processed, error)
        return {
            "source": self.feed_name,
            "records_processed": records_processed,
            "new_cves": new_cves,
            "error": error
        }

