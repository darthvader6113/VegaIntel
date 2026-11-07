"""
IOC Deduplication and Ingestion Engine.
Guarantees single canonical IOC records via upsert operations,
tracks every sighting immutably, and creates decoupled graph relationships.
Automatically correlates IOCs with CVEs and APT groups without deduplicating CVEs or APT groups.
"""
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from app.core.fingerprint import generate_fingerprint
from app.core.normalizer import normalize_ioc
from app.core.validator import calculate_dynamic_confidence, validate_ioc_evidence

logger = logging.getLogger("vegaintel.deduplicator")

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


class DeduplicationEngine:
    def __init__(self, db):
        self.db = db

    def _extract_cves_from_text_and_tags(self, text_snippets: List[str], tags: List[str]) -> Set[str]:
        """Extracts valid CVE patterns from free-form text and tags."""
        cves = set()
        for t in tags:
            for match in CVE_REGEX.findall(t):
                cves.add(match.upper())
        for snippet in text_snippets:
            if snippet:
                for match in CVE_REGEX.findall(str(snippet)):
                    cves.add(match.upper())
        return cves

    def _match_apt_groups(self, text_snippets: List[str], tags: List[str], malware: Optional[str]) -> Set[str]:
        """
        Correlates APT groups by matching aliases, group IDs, or associated malware families.
        Keeps APT groups pure and non-deduplicated.
        """
        matched_apts = set()
        try:
            apt_cursor = self.db.apt_groups.find({}, {"group_id": 1, "name": 1, "aliases": 1, "associated_malware": 1, "_id": 0})
            apt_list = list(apt_cursor)
        except Exception:
            apt_list = []

        combined_text = " ".join([str(s) for s in text_snippets if s] + tags).lower()
        malware_lower = (malware or "").lower()

        for group in apt_list:
            gid = group.get("group_id")
            gname = (group.get("name") or "").lower()
            aliases = [a.lower() for a in group.get("aliases", [])]

            # Match by direct group name or alias
            if gname and gname in combined_text:
                matched_apts.add(gid)
                continue
            for alias in aliases:
                if len(alias) >= 3 and alias in combined_text:
                    matched_apts.add(gid)
                    break

            # Match through known malware family usage
            if malware_lower and gid not in matched_apts:
                for assoc_mal in group.get("associated_malware", []):
                    if assoc_mal.lower() in malware_lower or malware_lower in assoc_mal.lower():
                        matched_apts.add(gid)
                        break

        return matched_apts

    def ingest_ioc_sighting(
        self,
        raw_ioc: str,
        source: str,
        ioc_type: Optional[str] = None,
        feed_confidence: int = 70,
        associated_cve: Optional[str] = None,
        associated_malware: Optional[str] = None,
        associated_apt: Optional[str] = None,
        threat_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        evidence_notes: str = "",
        observed_at: Optional[datetime] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Processes a raw sighting:
        1. Normalizes IOC and validates syntax against False Positive engine.
        2. Computes canonical fingerprint (normalized_type:normalized_value).
        3. Performs atomic MongoDB upsert on canonical IOC record (deduplication of IOCs).
        4. Inserts immutable sighting record.
        5. Performs deep correlation mapping: links IOCs with CVEs and APT groups.
        6. Note: APT groups and CVEs are never deduplicated into lossy hashes.
        Returns: (is_new_canonical_ioc, fingerprint, summary_dict)
        """
        observed_time = observed_at or datetime.now(timezone.utc)
        threat_types = threat_types or []
        tags = tags or []
        raw_payload = raw_payload or {}

        # 1. Normalize
        norm_type, norm_val = normalize_ioc(raw_ioc, ioc_type)

        # 2. Validate
        valid, reason = validate_ioc_evidence(norm_type, norm_val)
        if not valid:
            logger.debug(f"Rejected invalid IOC '{raw_ioc}': {reason}")
            return False, "", {"status": "rejected", "reason": reason}

        # 3. Compute Fingerprint
        fingerprint = f"{norm_type}:{norm_val}"

        # 4. Correlate CVEs and APT groups from payload and tags
        payload_snippets = [evidence_notes, str(raw_payload.get("name", "")), str(raw_payload.get("description", ""))]
        candidate_cves = self._extract_cves_from_text_and_tags(payload_snippets, tags)
        if associated_cve:
            candidate_cves.add(associated_cve.upper())

        candidate_apts = self._match_apt_groups(payload_snippets, tags, associated_malware)
        if associated_apt:
            candidate_apts.add(associated_apt)

        # 5. Atomic Upsert in MongoDB for Canonical IOC Record
        existing = self.db.iocs.find_one({"fingerprint": fingerprint})
        is_new_canonical = False

        if existing:
            # Existing Canonical IOC - Deduplicate and Update counts/confidence
            new_sighting_count = existing.get("sighting_count", 1) + 1
            existing_sources = set(existing.get("sources", []))
            existing_sources.add(source)
            unique_sources_count = len(existing_sources)

            new_confidence = calculate_dynamic_confidence(
                source_name=source,
                feed_confidence=feed_confidence,
                existing_confidence=existing.get("overall_confidence", 50),
                sighting_count=new_sighting_count
            )

            # Merge threat types and tags
            updated_threat_types = list(set(existing.get("threat_types", []) + threat_types))
            updated_tags = list(set(existing.get("tags", []) + tags))
            updated_cves = list(set(existing.get("associated_cves", []) + list(candidate_cves)))
            updated_apts = list(set(existing.get("associated_apt_groups", []) + list(candidate_apts)))
            existing_malware = existing.get("associated_malware", [])
            if associated_malware and associated_malware not in existing_malware:
                existing_malware.append(associated_malware)

            self.db.iocs.update_one(
                {"fingerprint": fingerprint},
                {
                    "$set": {
                        "last_seen": observed_time,
                        "overall_confidence": new_confidence,
                        "sighting_count": new_sighting_count,
                        "unique_sources_count": unique_sources_count,
                        "sources": list(existing_sources),
                        "threat_types": updated_threat_types,
                        "tags": updated_tags,
                        "associated_cves": updated_cves,
                        "associated_apt_groups": updated_apts,
                        "associated_malware": existing_malware,
                        "updated_at": datetime.now(timezone.utc)
                    }
                }
            )
            logger.debug(f"Deduplicated existing IOC '{fingerprint}'. Sightings: {new_sighting_count}")
        else:
            # New Canonical IOC - Create record
            is_new_canonical = True
            initial_confidence = calculate_dynamic_confidence(
                source_name=source,
                feed_confidence=feed_confidence,
                existing_confidence=0,
                sighting_count=1
            )
            new_ioc_doc = {
                "fingerprint": fingerprint,
                "ioc_type": norm_type,
                "ioc_value": norm_val,
                "first_seen": observed_time,
                "last_seen": observed_time,
                "sighting_count": 1,
                "unique_sources_count": 1,
                "sources": [source],
                "overall_confidence": initial_confidence,
                "threat_types": threat_types,
                "tags": tags,
                "associated_cves": list(candidate_cves),
                "associated_apt_groups": list(candidate_apts),
                "associated_malware": [associated_malware] if associated_malware else [],
                "status": "active",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            self.db.iocs.insert_one(new_ioc_doc)
            logger.info(f"Created new canonical IOC: {fingerprint}")

        # 6. Insert Immutable Sighting
        sighting_id = str(uuid.uuid4())
        sighting_doc = {
            "sighting_id": sighting_id,
            "ioc_fingerprint": fingerprint,
            "source": source,
            "observed_at": observed_time,
            "raw_payload": raw_payload,
            "feed_confidence": feed_confidence,
            "associated_cve": associated_cve or (list(candidate_cves)[0] if candidate_cves else None),
            "associated_malware": associated_malware,
            "evidence_notes": evidence_notes,
            "created_at": datetime.now(timezone.utc)
        }
        self.db.sightings.insert_one(sighting_doc)

        # 7. Decoupled Relationships Mapping (IOC <-> CVE, IOC <-> Malware, APT <-> IOC)
        for cve_id in candidate_cves:
            rel_id = f"ioc_cve:{fingerprint}:{cve_id}"
            self.db.relationships.update_one(
                {"relationship_id": rel_id},
                {
                    "$set": {
                        "source_type": "ioc",
                        "source_id": fingerprint,
                        "target_type": "cve",
                        "target_id": cve_id,
                        "relation_type": "associated_with",
                        "confidence": feed_confidence,
                        "last_verified": datetime.now(timezone.utc)
                    },
                    "$addToSet": {"evidence_sources": source},
                    "$setOnInsert": {
                        "relationship_id": rel_id,
                        "first_linked": observed_time
                    }
                },
                upsert=True
            )
            # Increment associated_ioc_count on the target CVE
            self.db.cves.update_one(
                {"cve_id": cve_id},
                {"$inc": {"associated_ioc_count": 1}}
            )

        if associated_malware:
            rel_id = f"ioc_malware:{fingerprint}:{associated_malware}"
            self.db.relationships.update_one(
                {"relationship_id": rel_id},
                {
                    "$set": {
                        "source_type": "ioc",
                        "source_id": fingerprint,
                        "target_type": "malware",
                        "target_id": associated_malware,
                        "relation_type": "infrastructure_of",
                        "confidence": feed_confidence,
                        "last_verified": datetime.now(timezone.utc)
                    },
                    "$addToSet": {"evidence_sources": source},
                    "$setOnInsert": {
                        "relationship_id": rel_id,
                        "first_linked": observed_time
                    }
                },
                upsert=True
            )

        for apt_id in candidate_apts:
            rel_id = f"apt_ioc:{apt_id}:{fingerprint}"
            self.db.relationships.update_one(
                {"relationship_id": rel_id},
                {
                    "$set": {
                        "source_type": "apt_group",
                        "source_id": apt_id,
                        "target_type": "ioc",
                        "target_id": fingerprint,
                        "relation_type": "uses_infrastructure",
                        "confidence": max(feed_confidence, 85),
                        "last_verified": datetime.now(timezone.utc)
                    },
                    "$addToSet": {"evidence_sources": source},
                    "$setOnInsert": {
                        "relationship_id": rel_id,
                        "first_linked": observed_time
                    }
                },
                upsert=True
            )
            # Update APT infrastructure count
            self.db.apt_groups.update_one(
                {"group_id": apt_id},
                {"$inc": {"infrastructure_count": 1}}
            )

            # If there are also candidate CVEs, correlate APT to CVEs
            for cve_id in candidate_cves:
                apt_cve_rel = f"apt_cve:{apt_id}:{cve_id}"
                self.db.relationships.update_one(
                    {"relationship_id": apt_cve_rel},
                    {
                        "$set": {
                            "source_type": "apt_group",
                            "source_id": apt_id,
                            "target_type": "cve",
                            "target_id": cve_id,
                            "relation_type": "exploits_cve",
                            "confidence": 90,
                            "last_verified": datetime.now(timezone.utc)
                        },
                        "$addToSet": {"evidence_sources": source},
                        "$setOnInsert": {
                            "relationship_id": apt_cve_rel,
                            "first_linked": observed_time
                        }
                    },
                    upsert=True
                )

        return is_new_canonical, fingerprint, {
            "is_new": is_new_canonical,
            "fingerprint": fingerprint,
            "type": norm_type,
            "value": norm_val,
            "source": source,
            "correlated_cves": list(candidate_cves),
            "correlated_apts": list(candidate_apts)
        }

