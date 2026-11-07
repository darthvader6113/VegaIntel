"""
Configuration settings for VegaIntel Threat Intelligence Platform.
Supports environment variables and .env file loading.
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


# Base directory pointing directly to backend folder to use backend/.env alone
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_ENV_FILE = os.path.join(BACKEND_DIR, ".env")


class Settings(BaseSettings):
    APP_NAME: str = "VegaIntel Threat Intelligence Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    
    # API Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database Configuration (Production MongoDB / Redis with auto in-memory fallback)
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "vegaintel_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # External OSINT & Threat Feed API Keys
    # 1. AlienVault OTX (https://otx.alienvault.com/api)
    OTX_API_KEY: Optional[str] = None
    
    # 2. NIST NVD API (https://nvd.nist.gov/developers/request-an-api-key)
    NVD_API_KEY: Optional[str] = None
    
    # 3. abuse.ch Auth-Key (Powers ThreatFox, URLhaus, MalwareBazaar: https://auth.abuse.ch/)
    ABUSE_CH_AUTH_KEY: Optional[str] = None
    
    # 4. GitHub Token (Increases rate limit for published PoC exploit search: https://github.com/settings/tokens)
    GITHUB_TOKEN: Optional[str] = None
    
    # 5. Optional VirusTotal Key
    VIRUSTOTAL_API_KEY: Optional[str] = None
    
    # 6. Google reCAPTCHA v3 Secret Key
    RECAPTCHA_SECRET_KEY: Optional[str] = None
    
    # Collection Intervals (minutes)
    CRON_COLLECTION_INTERVAL_MINUTES: int = 60
    
    # Security / JWT
    JWT_SECRET: str = "vegaintel_threat_platform_super_secret_jwt_key_2026_production"
    JWT_EXPIRE_HOURS: int = 24
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"
    ]

    model_config = SettingsConfigDict(
        env_file=BACKEND_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
