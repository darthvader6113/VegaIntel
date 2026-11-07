"""
Database connection manager with dual-mode support:
- Live MongoDB + Redis (for production / Docker)
- Transparent mongomock + fakeredis fallback (for local development without external dependencies)
"""
import logging
from typing import Any, Optional
import pymongo
from pymongo import MongoClient
import redis

from app.config import settings

logger = logging.getLogger("vegaintel.database")


class DatabaseManager:
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db: Any = None
        self.redis_client: Any = None
        self.is_mock_db: bool = False
        self.is_mock_redis: bool = False

    def connect(self):
        """Connect to MongoDB and Redis or initialize in-memory fallback."""
        # 1. MongoDB Connection
        try:
            logger.info(f"Attempting connection to MongoDB at {settings.MONGO_URI}...")
            # Short server selection timeout for quick detection of offline local MongoDB
            client = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=1500)
            client.admin.command("ping")
            self.client = client
            self.db = self.client[settings.MONGO_DB_NAME]
            self.is_mock_db = False
            logger.info("Successfully connected to production MongoDB.")
        except Exception as e:
            logger.warning(f"Production MongoDB unavailable ({e}). Initializing high-fidelity mongomock storage...")
            try:
                import mongomock
                self.client = mongomock.MongoClient()
                self.db = self.client[settings.MONGO_DB_NAME]
                self.is_mock_db = True
                logger.info("mongomock initialized successfully.")
            except ImportError:
                logger.critical("mongomock not installed and MongoDB offline!")
                raise

        # 2. Redis Connection
        try:
            logger.info(f"Attempting connection to Redis at {settings.REDIS_URL}...")
            r = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1.5)
            r.ping()
            self.redis_client = r
            self.is_mock_redis = False
            logger.info("Successfully connected to production Redis.")
        except Exception as e:
            logger.warning(f"Production Redis unavailable ({e}). Initializing fakeredis...")
            try:
                import fakeredis
                self.redis_client = fakeredis.FakeRedis(decode_responses=True)
                self.is_mock_redis = True
                logger.info("fakeredis initialized successfully.")
            except ImportError:
                logger.warning("fakeredis not installed. Redis cache will be disabled.")
                self.redis_client = None

        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create critical indexes for high-throughput deduplication and correlation."""
        if self.db is None:
            return
            
        try:
            # Canonical IOCs collection: unique index on fingerprint
            self.db.iocs.create_index([("fingerprint", pymongo.ASCENDING)], unique=True)
            self.db.iocs.create_index([("ioc_type", pymongo.ASCENDING)])
            self.db.iocs.create_index([("ioc_value", pymongo.ASCENDING)])
            self.db.iocs.create_index([("associated_cves", pymongo.ASCENDING)])
            self.db.iocs.create_index([("overall_confidence", pymongo.DESCENDING)])
            self.db.iocs.create_index([("sighting_count", pymongo.DESCENDING)])
            self.db.iocs.create_index([("last_seen", pymongo.DESCENDING)])

            # Sightings collection: index on fingerprint and observed_at
            self.db.sightings.create_index([("ioc_fingerprint", pymongo.ASCENDING)])
            self.db.sightings.create_index([("source", pymongo.ASCENDING)])
            self.db.sightings.create_index([("observed_at", pymongo.DESCENDING)])
            self.db.sightings.create_index([("associated_cve", pymongo.ASCENDING)])

            # Relationships collection: compound index on source, target, and relationship_type
            self.db.relationships.create_index([("source_id", pymongo.ASCENDING), ("target_id", pymongo.ASCENDING), ("relationship_type", pymongo.ASCENDING)], unique=True)
            self.db.relationships.create_index([("source_type", pymongo.ASCENDING)])
            self.db.relationships.create_index([("target_type", pymongo.ASCENDING)])
            self.db.relationships.create_index([("relationship_type", pymongo.ASCENDING)])
            self.db.relationships.create_index([("relation_type", pymongo.ASCENDING)])

            # CVEs collection: unique index on cve_id
            self.db.cves.create_index([("cve_id", pymongo.ASCENDING)], unique=True)
            self.db.cves.create_index([("cvss_score", pymongo.DESCENDING)])
            self.db.cves.create_index([("severity", pymongo.ASCENDING)])

            # APT Groups & Malware
            self.db.apt_groups.create_index([("group_id", pymongo.ASCENDING)], unique=True)
            self.db.malware.create_index([("malware_id", pymongo.ASCENDING)], unique=True)
            self.db.poc_references.create_index([("cve_id", pymongo.ASCENDING)])
            self.db.feed_status.create_index([("feed_name", pymongo.ASCENDING)], unique=True)
            
            logger.info("Database indexes ensured successfully.")
        except Exception as e:
            logger.warning(f"Index creation note: {e}")

    def close(self):
        if self.client:
            self.client.close()
            logger.info("Database connection closed.")


db_manager = DatabaseManager()


def get_db():
    """Dependency injector for FastAPI endpoints."""
    return db_manager.db


def get_redis():
    """Dependency injector for Redis cache."""
    return db_manager.redis_client

