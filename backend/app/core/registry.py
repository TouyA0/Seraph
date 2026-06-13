from app.core.connector import BaseConnector
from app.core.detector import ArtifactType
from app.modules.ip.internetdb import InternetDBConnector
from app.modules.ip.bgpview import IPApiConnector
from app.modules.ip.abuseipdb import AbuseIPDBConnector
from app.modules.ip.censys import CensysConnector
from app.modules.ip.shodan import ShodanConnector
from app.modules.domain.rdap import RDAPConnector
from app.modules.domain.crtsh import CrtShConnector
from app.modules.shared.threatfox import ThreatFoxConnector
from app.modules.shared.pulsedive import PulsediveConnector
from app.modules.shared.virustotal import VirusTotalConnector
from app.modules.shared.otx import OTXConnector
from app.modules.shared.urlscan import URLScanConnector

_ALL_CONNECTORS: list[BaseConnector] = [
    # Sans clé
    InternetDBConnector(),
    IPApiConnector(),
    RDAPConnector(),
    CrtShConnector(),
    PulsediveConnector(),
    # Clé requise
    VirusTotalConnector(),
    AbuseIPDBConnector(),
    OTXConnector(),
    URLScanConnector(),
    CensysConnector(),
    ShodanConnector(),
    ThreatFoxConnector(),
]


def get_connectors(artifact_type: ArtifactType) -> list[BaseConnector]:
    """Retourne les connecteurs compatibles ET configurés."""
    return [c for c in _ALL_CONNECTORS if c.supports(artifact_type) and c.is_configured()]


def get_all_connectors(artifact_type: ArtifactType, only_unconfigured: bool = False) -> list[BaseConnector]:
    """Retourne tous les connecteurs compatibles (configurés ou non)."""
    compatible = [c for c in _ALL_CONNECTORS if c.supports(artifact_type)]
    if only_unconfigured:
        return [c for c in compatible if not c.is_configured()]
    return compatible


def get_connector_catalog() -> list[dict]:
    """Catalogue complet pour la page de réglages."""
    return [
        {
            "name": c.name,
            "requires_key": c.requires_key,
            "is_active": c.is_active,
            "configured": c.is_configured(),
            "supported_types": [t.value for t in c.supported_types],
        }
        for c in _ALL_CONNECTORS
    ]
