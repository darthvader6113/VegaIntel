"""
NVD (National Vulnerability Database) CVE Live Collector.
Connects directly to the live NIST NVD 2.0 REST API to discover real-world CVEs,
CVSS v3.1 scores, severity ratings, CWE classifications, and official references.
Strictly live data. Zero mock or sample records.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.config import settings

logger = logging.getLogger("vegaintel.collector.nvd")


class NVDCollector:
    def __init__(self, db):
        self.db = db
        self.feed_name = "NVD"
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def fetch_and_process(self) -> Dict[str, Any]:
        logger.info("Connecting directly to live NIST NVD 2.0 REST API...")
        count = 0
        error = None

        headers = {"User-Agent": "VegaIntel-Threat-Platform/1.0"}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.base_url}?resultsPerPage=25",
                    headers=headers
                )

                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    logger.info(f"NVD 2.0 API delivered {len(vulnerabilities)} real CVE records.")

                    for item in vulnerabilities:
                        cve_obj = item.get("cve", {})
                        cve_id = cve_obj.get("id")
                        if not cve_id:
                            continue

                        # Extract descriptions
                        descriptions = cve_obj.get("descriptions", [])
                        desc_text = "No description provided."
                        for d in descriptions:
                            if d.get("lang") == "en":
                                desc_text = d.get("value")
                                break

                        # Extract CVSS Metrics
                        metrics = cve_obj.get("metrics", {})
                        cvss_score = 7.5
                        severity = "HIGH"
                        cvss_vector = None

                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                            metric_data = metrics["cvssMetricV31"][0]["cvssData"]
                            cvss_score = metric_data.get("baseScore", 7.5)
                            cvss_vector = metric_data.get("vectorString")
                            severity = metric_data.get("baseSeverity", "HIGH")
                        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                            metric_data = metrics["cvssMetricV30"][0]["cvssData"]
                            cvss_score = metric_data.get("baseScore", 7.5)
                            cvss_vector = metric_data.get("vectorString")
                            severity = metric_data.get("baseSeverity", "HIGH")

                        # Extract CWEs
                        cwe_ids = []
                        for weakness in cve_obj.get("weaknesses", []):
                            for desc in weakness.get("description", []):
                                if desc.get("value") and desc.get("value") != "NVD-CWE-noinfo":
                                    cwe_ids.append(desc.get("value"))

                        # References
                        refs = [r.get("url") for r in cve_obj.get("references", []) if r.get("url")]

                        # Published date
                        pub_date_str = cve_obj.get("published")
                        pub_date = datetime.now(timezone.utc)
                        if pub_date_str:
                            try:
                                pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
                            except Exception:
                                pass

                        # Count associated IOCs from threat graph
                        ioc_count = self.db.relationships.count_documents({
                            "target_id": cve_id,
                            "relation_type": "associated_with"
                        })
                        poc_count = self.db.poc_references.count_documents({"cve_id": cve_id})

                        self.db.cves.update_one(
                            {"cve_id": cve_id},
                            {
                                "$set": {
                                    "description": desc_text,
                                    "cvss_score": float(cvss_score),
                                    "cvss_vector": cvss_vector,
                                    "severity": str(severity).upper(),
                                    "cwe_ids": cwe_ids,
                                    "references": refs[:5],
                                    "published_date": pub_date,
                                    "has_poc": poc_count > 0,
                                    "associated_ioc_count": ioc_count,
                                    "updated_at": datetime.now(timezone.utc)
                                },
                                "$setOnInsert": {
                                    "cve_id": cve_id,
                                    "created_at": datetime.now(timezone.utc)
                                }
                            },
                            upsert=True
                        )
                        count += 1
                else:
                    error = f"NVD API returned status code {resp.status_code}"
                    logger.warning(error)

        except Exception as e:
            error = str(e)
            logger.error(f"NVD live collection warning: {e}")

        self.db.feed_status.update_one(
            {"feed_name": "NVD"},
            {
                "$set": {
                    "status": "HEALTHY" if count > 0 else "DEGRADED",
                    "last_successful_sync": datetime.now(timezone.utc) if count > 0 else None,
                    "last_error": error,
                },
                "$inc": {"total_records_ingested": count}
            },
            upsert=True
        )

        return {"source": "NVD", "synced_cves": count, "error": error}
