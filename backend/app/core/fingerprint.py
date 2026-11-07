"""
Fingerprint Generation Engine.
Implements the canonical fingerprint formula:
fingerprint = normalized_ioc_type + ":" + normalized_ioc_value
"""
from typing import Optional
from app.core.normalizer import normalize_ioc


def generate_fingerprint(raw_value: str, ioc_type: Optional[str] = None) -> str:
    """
    Computes deterministic canonical fingerprint for any given IOC.
    Example:
      generate_fingerprint("oast[.]live", "domain") -> "domain:oast.live"
      generate_fingerprint("198.51.100.23") -> "ip:198.51.100.23"
      generate_fingerprint("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        -> "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    """
    norm_type, norm_value = normalize_ioc(raw_value, ioc_type)
    return f"{norm_type}:{norm_value}"

