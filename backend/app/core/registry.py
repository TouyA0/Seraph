from app.core.connector import BaseConnector
from app.core.detector import ArtifactType
from app.modules.ip.internetdb import InternetDBConnector
from app.modules.ip.bgpview import IPApiConnector
from app.modules.domain.rdap import RDAPConnector
from app.modules.domain.crtsh import CrtShConnector
from app.modules.shared.threatfox import ThreatFoxConnector
from app.modules.shared.pulsedive import PulsediveConnector

_ALL_CONNECTORS: list[BaseConnector] = [
    InternetDBConnector(),
    IPApiConnector(),
    RDAPConnector(),
    CrtShConnector(),
    ThreatFoxConnector(),
    PulsediveConnector(),
]


def get_connectors(artifact_type: ArtifactType) -> list[BaseConnector]:
    return [c for c in _ALL_CONNECTORS if c.supports(artifact_type) and c.is_configured()]
