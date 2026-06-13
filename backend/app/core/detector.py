import re
from enum import Enum


class ArtifactType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"
    ASN = "asn"
    UNKNOWN = "unknown"


_IPV4 = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ASN = re.compile(r"^AS\d+$", re.IGNORECASE)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def detect(value: str) -> ArtifactType:
    v = value.strip()

    if _CVE.match(v):
        return ArtifactType.CVE
    if _ASN.match(v):
        return ArtifactType.ASN
    if _IPV4.match(v) or _IPV6.match(v):
        return ArtifactType.IP
    if _MD5.match(v) or _SHA1.match(v) or _SHA256.match(v):
        return ArtifactType.HASH
    if _EMAIL.match(v):
        return ArtifactType.EMAIL
    if _URL.match(v):
        return ArtifactType.URL
    if _DOMAIN.match(v):
        return ArtifactType.DOMAIN

    return ArtifactType.UNKNOWN


def detect_all(value: str) -> list[ArtifactType]:
    """Return ordered list of possible types (most specific first)."""
    t = detect(value)
    if t != ArtifactType.UNKNOWN:
        return [t]
    return [ArtifactType.UNKNOWN]
