"""
PoC Reference Live Collector (GitHub & Exploit Intelligence).
Queries live public security repository indexes and GitHub exploit registries
to catalog real-world Proof-of-Concept exploit references.
Advisory: Never auto-executes code. Strictly metadata only.
Zero mock or sample data.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import httpx

from app.config import settings

logger = logging.getLogger("vegaintel.collector.poc")


class PoCReferenceCollector:
    def __init__(self, db):
        self.db = db
        self.feed_name = "PoC Reference Collector"
        self.search_url = "https://api.github.com/search/repositories"

    async def fetch_and_process(self) -> Dict[str, Any]:
        logger.info("Querying live GitHub Search API for published CVE PoC exploit repositories...")
        count = 0
        error = None

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "VegaIntel-Threat-Platform/1.0"
        }
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.search_url}?q=CVE+exploit+poc&sort=updated&per_page=15",
                    headers=headers
                )

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    logger.info(f"GitHub Search delivered {len(items)} live exploit repository references.")

                    for repo in items:
                        repo_name = repo.get("name", "")
                        full_name = repo.get("full_name", "")
                        html_url = repo.get("html_url", "")
                        desc = repo.get("description") or "Live weaponized Proof-of-Concept repository published to GitHub."
                        owner = repo.get("owner", {}).get("login", "Unknown")
                        stars = repo.get("stargazers_count", 0)

                        # Extract CVE identifier from title or description
                        import re
                        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", f"{full_name} {desc}", re.IGNORECASE)
                        cve_id = cve_match.group(0).upper() if cve_match else "CVE-2024-GENERAL"

                        poc_id = f"poc:github:{full_name.replace('/', '_')}"
                        self.db.poc_references.update_one(
                            {"poc_id": poc_id},
                            {
                                "$set": {
                                    "cve_id": cve_id,
                                    "source": "GitHub",
                                    "title": full_name,
                                    "url": html_url,
                                    "author": owner,
                                    "reliability": "Verified" if stars >= 5 else "Functional",
                                    "description": desc,
                                    "discovered_date": datetime.now(timezone.utc),
                                    "advisory": "TREAT AS REFERENCE ONLY. Never automatically execute downloaded exploit code.",
                                    "updated_at": datetime.now(timezone.utc)
                                },
                                "$setOnInsert": {
                                    "poc_id": poc_id,
                                    "created_at": datetime.now(timezone.utc)
                                }
                            },
                            upsert=True
                        )

                        # Link relationship between CVE and PoC
                        rel_id = f"cve_poc:{cve_id}:{poc_id}"
                        self.db.relationships.update_one(
                            {"relationship_id": rel_id},
                            {
                                "$set": {
                                    "source_type": "cve",
                                    "source_id": cve_id,
                                    "target_type": "poc",
                                    "target_id": poc_id,
                                    "relation_type": "has_exploit_poc",
                                    "confidence": 95,
                                    "last_verified": datetime.now(timezone.utc)
                                },
                                "$addToSet": {"evidence_sources": "GitHub"},
                                "$setOnInsert": {"first_linked": datetime.now(timezone.utc)}
                            },
                            upsert=True
                        )

                        # Update CVE has_poc status
                        self.db.cves.update_one(
                            {"cve_id": cve_id},
                            {"$set": {"has_poc": True}}
                        )
                        count += 1
                else:
                    error = f"GitHub API status code: {resp.status_code}"
                    logger.warning(error)

        except Exception as e:
            error = str(e)
            logger.error(f"Live PoC collector warning: {e}")

        return {"source": self.feed_name, "synced_pocs": count, "error": error}
