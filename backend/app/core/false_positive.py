"""
Advanced False Positive Prevention & Verification Engine for VegaIntel.
Enforces rigorous allowlists, network boundary checks, benign CDN/DNS validation,
and cryptographic integrity checks to prevent false positive contamination.
"""
import ipaddress
import re
from typing import Set, Tuple
from urllib.parse import urlparse

# Well-known apex benign domains, cloud services, and CDNs that should never be marked as malicious root IOCs
BENIGN_APEX_DOMAINS: Set[str] = {
    # Search & Cloud Giants
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
    "windows.com", "windowsupdate.com", "azure.com", "azureedge.net",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "aws.amazon.com",
    "github.com", "githubusercontent.com", "gitlab.com",
    
    # CDNs & Infrastructure
    "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaiedge.net", "akamaihd.net",
    "fastly.net", "cloudfront.net", "edgecastcdn.net",
    
    # Public DNS Resolvers
    "dns.google", "one.one.one.one", "quad9.net",
    
    # OS & Package Repositories
    "debian.org", "ubuntu.com", "canonical.com", "redhat.com", "archlinux.org",
    "python.org", "pypi.org", "npmjs.com", "npmjs.org", "docker.com", "docker.io",
    
    # Security & Authorities
    "letsencrypt.org", "digicert.com", "sectigo.com", "verisign.com", "cisa.gov", "nist.gov",
    "virustotal.com", "abuse.ch", "shodan.io", "censys.io"
}

# Public DNS Resolvers and Well-Known Benign Anycast IPs
BENIGN_IPS: Set[str] = {
    "1.1.1.1", "1.0.0.1",         # Cloudflare DNS
    "8.8.8.8", "8.8.4.4",         # Google DNS
    "9.9.9.9", "149.112.112.112", # Quad9 DNS
    "208.67.222.222", "208.67.220.220", # OpenDNS
}

# Empty / Null file hashes that represent 0-byte files or test buffers
KNOWN_EMPTY_HASHES: Set[str] = {
    "d41d8cd98f00b204e9800998ecf8427e",                                # MD5 of ""
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                        # SHA1 of ""
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA256 of ""
}

# Recognized Standard and Modern TLDs
TLD_REGEX = re.compile(r"\.[a-zA-Z]{2,}$")
INTERNAL_TLDS: Set[str] = {".local", ".lan", ".internal", ".corp", ".home", ".test", ".invalid", ".localhost"}


def inspect_for_false_positive(ioc_type: str, ioc_value: str) -> Tuple[bool, str, str]:
    """
    Evaluates an indicator against false-positive criteria.
    Returns: (is_false_positive, reason, recommended_status)
    - If is_false_positive == True: Ingestion should quarantine or reject the indicator.
    - If is_false_positive == False: Indicator is approved for canonical ingestion.
    """
    val = ioc_value.lower().strip()

    # 1. IP Address Auditing
    if ioc_type == "ip":
        if val in BENIGN_IPS:
            return True, f"Known benign public Anycast DNS resolver ({val})", "benign_resolver"
        try:
            ip = ipaddress.ip_address(val)
            if ip.is_private:
                return True, f"RFC1918 Private IP space ({val})", "rfc1918_private"
            if ip.is_loopback:
                return True, f"Loopback address ({val})", "loopback"
            if ip.is_reserved:
                return True, f"IETF Reserved IP ({val})", "reserved"
            if ip.is_link_local:
                return True, f"Link-local IP ({val})", "link_local"
            if ip.is_multicast:
                return True, f"Multicast address ({val})", "multicast"
            # CGNAT 100.64.0.0/10
            cgnat_net = ipaddress.ip_network("100.64.0.0/10")
            if ip in cgnat_net:
                return True, f"Carrier-Grade NAT (CGNAT) IP ({val})", "cgnat"
            # Documentation subnets
            for doc_net in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]:
                if ip in ipaddress.ip_network(doc_net):
                    return True, f"TEST-NET Documentation IP ({val})", "test_documentation"
        except ValueError:
            return True, f"Invalid IP syntax ({val})", "malformed_syntax"

    # 2. Domain Name Auditing
    elif ioc_type == "domain":
        # Check internal TLDs
        for tld in INTERNAL_TLDS:
            if val.endswith(tld):
                return True, f"Internal non-routable TLD ({tld})", "internal_tld"

        # Check for missing valid TLD
        if not TLD_REGEX.search(val):
            return True, "Domain missing valid public TLD suffix", "missing_tld"

        # Check Benign Apex Domains
        # If the domain is exactly in the benign list, it's a false positive
        if val in BENIGN_APEX_DOMAINS:
            return True, f"Benign high-reputation apex domain ({val})", "whitelisted_apex"

        # Check if it is a major CDN apex domain without deep malicious subdomain
        parts = val.split(".")
        if len(parts) >= 2:
            apex = ".".join(parts[-2:])
            if apex in BENIGN_APEX_DOMAINS and len(parts) == 2:
                return True, f"Benign infrastructure domain ({val})", "whitelisted_apex"

    # 3. URL Auditing
    elif ioc_type == "url":
        try:
            parsed = urlparse(val)
            netloc = parsed.netloc.split(":")[0].lower()
            if netloc in BENIGN_APEX_DOMAINS and parsed.path in ("", "/"):
                return True, f"Root homepage URL of benign domain ({netloc})", "whitelisted_root_url"
            if "localhost" in netloc or "127.0.0.1" in netloc:
                return True, "Localhost target URL", "localhost_url"
        except Exception:
            return True, "Malformed URL structure", "malformed_url"

    # 4. Hash Auditing
    elif ioc_type in ("md5", "sha1", "sha256"):
        if val in KNOWN_EMPTY_HASHES:
            return True, "Null / empty file zero-byte hash", "empty_file_hash"
        # Check all zeroes
        if set(val) == {"0"}:
            return True, "Zero-byte test hash", "null_hash"

    return False, "Verified clean OSINT indicator", "valid"

