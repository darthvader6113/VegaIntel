"""
IOC Parser and Normalizer.
Handles defanging, whitespace trimming, lowercase casting, and strict type detection.
"""
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# Regular expressions for IOC validation
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def defang(value: str) -> str:
    """Removes common defanging protections applied by security researchers."""
    if not value:
        return ""
    val = value.strip()
    # Replace bracketed dots, colons, slashes first
    val = val.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    val = val.replace("[:]", ":").replace("(:)", ":")
    val = val.replace("[/]", "/").replace("(/)", "/")
    # Replace defanged protocols
    val = re.sub(r"^hxxps?://", lambda m: "https://" if "hxxps" in m.group(0).lower() else "http://", val, flags=re.IGNORECASE)
    return val


def detect_ioc_type(raw_value: str) -> str:
    """Detects the IOC type based on structure and regex matching."""
    val = defang(raw_value).strip()
    
    # Check hashes first
    if SHA256_REGEX.match(val):
        return "sha256"
    if MD5_REGEX.match(val):
        return "md5"
    if SHA1_REGEX.match(val):
        return "sha1"
        
    # Check IP
    try:
        ipaddress.ip_address(val)
        return "ip"
    except ValueError:
        pass
        
    # Check URL
    if val.startswith("http://") or val.startswith("https://") or "/" in val:
        return "url"
        
    # Check Domain
    if DOMAIN_REGEX.match(val):
        return "domain"
        
    # Default fallback
    return "unknown"


def normalize_ioc(raw_value: str, forced_type: Optional[str] = None) -> Tuple[str, str]:
    """
    Normalizes an IOC string and returns (normalized_type, normalized_value).
    """
    clean = defang(raw_value).strip()
    detected_type = (forced_type or detect_ioc_type(clean)).lower()

    if detected_type in ("md5", "sha1", "sha256"):
        return detected_type, clean.lower()

    if detected_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(clean)
            return "ip", str(ip_obj)
        except ValueError:
            return "ip", clean.strip()

    if detected_type == "domain":
        # Remove any protocol or path if mistakenly present
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        clean = clean.split("/")[0].split(":")[0].strip().lower()
        if clean.endswith("."):
            clean = clean[:-1]
        return "domain", clean

    if detected_type == "url":
        clean_url = clean
        if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
            clean_url = "http://" + clean_url
        try:
            parsed = urlparse(clean_url)
            norm_netloc = parsed.netloc.lower()
            norm_path = parsed.path or "/"
            if norm_path != "/" and norm_path.endswith("/"):
                norm_path = norm_path.rstrip("/")
            normalized = f"{parsed.scheme.lower()}://{norm_netloc}{norm_path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return "url", normalized
        except Exception:
            return "url", clean.lower().rstrip("/")

    return detected_type, clean.lower()
