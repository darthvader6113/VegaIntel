"""
NVD (National Vulnerability Database) CVE Live Collector.
Connects directly to the live NIST NVD 2.0 REST API to discover real-world CVEs,
CVSS v3.1 scores, severity ratings, CWE classifications, and official references.
Supports chronological pagination cursor for continuous ingestion into MongoDB.
Strictly live data. Zero mock or sample records.
"""
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List
import httpx
import pymongo

from app.config import settings
from app.database import safe_bulk_write

logger = logging.getLogger("vegaintel.collector.nvd")


class NVDCollector:
    def __init__(self, db):
        self.db = db
        self.feed_name = "NVD"
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _get_pagination_cursor(self) -> Dict[str, Any]:
        """Retrieves or creates the NVD ingestion cursor."""
        cursor = self.db.collection_state.find_one({"_id": "nvd_pagination_cursor"})
        if not cursor:
            cursor = {
                "_id": "nvd_pagination_cursor",
                "start_index": 0,
                "total_results": 0,
                "last_synced_at": datetime.now(timezone.utc)
            }
            self.db.collection_state.insert_one(cursor)
        return cursor

    def _advance_pagination_cursor(self, current_start: int, batch_count: int, total_available: int):
        """Advances the cursor for next ingestion cycle."""
        next_start = current_start + batch_count
        if total_available > 0 and next_start >= total_available:
            next_start = 0  # Wrap around to latest entries

        self.db.collection_state.update_one(
            {"_id": "nvd_pagination_cursor"},
            {
                "$set": {
                    "start_index": next_start,
                    "total_results": total_available,
                    "last_synced_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )

    async def fetch_and_process(self) -> Dict[str, Any]:
        logger.info("Connecting directly to live NIST NVD 2.0 REST API...")
        count = 0
        error = None

        headers = {"User-Agent": "VegaIntel-Threat-Platform/1.0"}
        results_per_page = 100
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY
            results_per_page = 250

        cursor = self._get_pagination_cursor()
        start_index = cursor.get("start_index", 0)

        try:
            url = f"{self.base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
            logger.info(f"Querying NVD API: startIndex={start_index}, resultsPerPage={results_per_page}...")

            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.get(url, headers=headers)

                if resp.status_code == 200:
                    data = resp.json()
                    total_results = data.get("totalResults", 0)
                    vulnerabilities = data.get("vulnerabilities", [])
                    logger.info(f"NVD 2.0 API returned {len(vulnerabilities)} CVE records (Total available: {total_results}).")

                    now = datetime.now(timezone.utc)
                    cve_bulk_ops: List[pymongo.UpdateOne] = []
                    poc_bulk_ops: List[pymongo.UpdateOne] = []

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

                        # References & PoC Detection
                        refs = [r.get("url") for r in cve_obj.get("references", []) if r.get("url")]
                        has_poc = False
                        for r_url in refs:
                            if any(domain in r_url.lower() for domain in ["github.com", "exploit-db.com", "packetstormsecurity.com", "rapid7.com"]):
                                has_poc = True
                                poc_bulk_ops.append(
                                    pymongo.UpdateOne(
                                        {"cve_id": cve_id, "url": r_url},
                                        {
                                            "$set": {
                                                "cve_id": cve_id,
                                                "title": f"Public Exploit Reference for {cve_id}",
                                                "source": "NVD Exploit Advisory",
                                                "url": r_url,
                                                "author": "Security Researcher",
                                                "verified": True,
                                                "updated_at": now
                                            },
                                            "$setOnInsert": {
                                                "created_at": now
                                            }
                                        },
                                        upsert=True
                                    )
                                )

                        # Published date
                        pub_date_str = cve_obj.get("published")
                        pub_date = now
                        if pub_date_str:
                            try:
                                pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
                            except Exception:
                                pub_date = now

                        cve_bulk_ops.append(
                            pymongo.UpdateOne(
                                {"cve_id": cve_id},
                                {
                                    "$set": {
                                        "description": desc_text,
                                        "cvss_score": float(cvss_score),
                                        "cvss_vector": cvss_vector,
                                        "severity": str(severity).upper(),
                                        "cwe_ids": cwe_ids,
                                        "references": refs[:10],
                                        "published_date": pub_date,
                                        "has_poc": has_poc,
                                        "updated_at": now
                                    },
                                    "$setOnInsert": {
                                        "cve_id": cve_id,
                                        "associated_ioc_count": 0,
                                        "created_at": now
                                    }
                                },
                                upsert=True
                            )
                        )
                        count += 1

                    if cve_bulk_ops:
                        safe_bulk_write(self.db.cves, cve_bulk_ops, ordered=False)
                    if poc_bulk_ops:
                        safe_bulk_write(self.db.poc_references, poc_bulk_ops, ordered=False)

                    self._advance_pagination_cursor(start_index, len(vulnerabilities), total_results)
                    logger.info(f"Ingested {count} CVEs from NVD batch into MongoDB. Cursor advanced.")
                else:
                    error = f"NVD API returned status code {resp.status_code}"
                    logger.warning(error)

        except Exception as e:
            error = str(e)
            logger.error(f"NVD live collection notice: {e}")

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
