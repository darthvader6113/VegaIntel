"""
Collection Engine & Ingestion Orchestrator.
Executes the live OSINT collection and deduplication pipeline across genuine feeds:
- CISA KEV (Real-world actively exploited CVEs)
- Feodo Tracker (Real live botnet C2s)
- OpenPhish (Real live phishing & malware URLs)
- Emerging Threats (Real live malicious scanner & adversary IPs)
- AlienVault OTX, ThreatFox, URLhaus
- MITRE ATT&CK & Verified PoCs
"""
import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.emerging_threats import EmergingThreatsCollector
from app.collectors.feodotracker import FeodoTrackerCollector
from app.collectors.malwarebazaar import MalwareBazaarCollector
from app.collectors.mitre_attack import MitreAttackCollector
from app.collectors.nvd import NVDCollector
from app.collectors.openphish import OpenPhishCollector
from app.collectors.otx import AlienVaultOTXCollector
from app.collectors.poc_collector import PoCReferenceCollector
from app.collectors.threatfox import ThreatFoxCollector
from app.collectors.urlhaus import URLhausCollector
from app.config import settings

logger = logging.getLogger("vegaintel.orchestrator")


class IntelligenceOrchestrator:
    def __init__(self, db):
        self.db = db
        self.scheduler = AsyncIOScheduler()
        self.is_running_sync = False

    def setup_scheduler(self):
        """Configures periodic background sync based on settings interval."""
        interval = max(5, settings.CRON_COLLECTION_INTERVAL_MINUTES)
        self.scheduler.add_job(
            self.run_full_cycle,
            "interval",
            minutes=interval,
            id="threat_intelligence_cycle",
            replace_existing=True,
            next_run_time=datetime.now()
        )
        self.scheduler.start()
        logger.info(f"Automated threat collection scheduled every {interval} minutes.")

    async def run_full_cycle(self) -> Dict[str, Any]:
        """Runs the complete collection and correlation pipeline with strictly live data."""
        if self.is_running_sync:
            logger.warning("Ingestion cycle already in progress. Skipping overlapping trigger.")
            return {"status": "in_progress"}

        self.is_running_sync = True
        start_time = datetime.now(timezone.utc)
        logger.info(">>> Starting VegaIntel Live OSINT Collection & Deduplication Cycle <<<")

        try:
            # Step 1: Discovered actively exploited CVEs from CISA KEV & NVD
            cisa = CisaKevCollector(self.db)
            await cisa.fetch_and_process()

            nvd = NVDCollector(self.db)
            await nvd.fetch_and_process()

            # Step 2: MITRE ATT&CK Threat Actor context
            mitre = MitreAttackCollector(self.db)
            await mitre.fetch_and_process()

            # Step 3: Exploit PoC references
            poc = PoCReferenceCollector(self.db)
            await poc.fetch_and_process()

            # Step 4: Fan-out collection across genuine OSINT feeds
            feodo = FeodoTrackerCollector(self.db)
            openphish = OpenPhishCollector(self.db)
            et = EmergingThreatsCollector(self.db)
            mb = MalwareBazaarCollector(self.db)
            otx = AlienVaultOTXCollector(self.db)
            threatfox = ThreatFoxCollector(self.db)
            urlhaus = URLhausCollector(self.db)

            results = await asyncio.gather(
                feodo.fetch_and_process(),
                openphish.fetch_and_process(),
                et.fetch_and_process(),
                mb.fetch_and_process(),
                otx.fetch_and_process(),
                threatfox.fetch_and_process(),
                urlhaus.fetch_and_process(),
                return_exceptions=True
            )

            # Step 5: Post-ingestion correlation refresh (update CVE associated counts)
            cves = list(self.db.cves.find({}, {"cve_id": 1}))
            for c in cves:
                cid = c["cve_id"]
                ioc_count = self.db.iocs.count_documents({"associated_cves": cid})
                if ioc_count == 0:
                    ioc_count = self.db.relationships.count_documents({
                        "target_id": cid,
                        "relationship_type": {"$in": ["associated_with", "indicates", "targets"]}
                    })
                self.db.cves.update_one({"cve_id": cid}, {"$set": {"associated_ioc_count": ioc_count}})

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(f">>> Live Intelligence cycle completed in {duration:.2f} seconds <<<")

            return {
                "status": "success",
                "duration_seconds": duration,
                "feed_results": [r for r in results if isinstance(r, dict)]
            }

        except Exception as e:
            logger.error(f"Error during intelligence cycle: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
        finally:
            self.is_running_sync = False
