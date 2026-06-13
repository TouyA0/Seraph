import pytest
from app.core.detector import ArtifactType, detect


@pytest.mark.parametrize("value,expected", [
    ("185.220.101.5", ArtifactType.IP),
    ("2001:db8::1", ArtifactType.IP),
    ("evil.com", ArtifactType.DOMAIN),
    ("secure-login.ru", ArtifactType.DOMAIN),
    ("http://x.co/pay", ArtifactType.URL),
    ("https://phish.example.com/click", ArtifactType.URL),
    ("d41d8cd98f00b204e9800998ecf8427e", ArtifactType.HASH),  # MD5
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ArtifactType.HASH),  # SHA1
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ArtifactType.HASH),  # SHA256
    ("ceo@corp.com", ArtifactType.EMAIL),
    ("CVE-2024-3094", ArtifactType.CVE),
    ("cve-2021-44228", ArtifactType.CVE),
    ("AS15169", ArtifactType.ASN),
])
def test_detect(value, expected):
    assert detect(value) == expected
