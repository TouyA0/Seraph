from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel

from app.core.detector import ArtifactType


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    REPUTATION = "reputation"
    EXPOSURE = "exposure"
    VULNERABILITY = "vulnerability"
    NETWORK = "network"
    LEAK = "leak"
    BEHAVIOR = "behavior"


class Finding(BaseModel):
    severity: Severity
    category: FindingCategory
    label: str
    source: str
    evidence: str | None = None


class ConnectorResult(BaseModel):
    connector: str
    status: str  # "ok" | "error" | "unconfigured" | "skipped"
    artifact: str
    artifact_type: ArtifactType
    raw: dict[str, Any] | None = None
    findings: list[Finding] = []
    latency_ms: int | None = None
    error: str | None = None


class BaseConnector(ABC):
    name: str
    supported_types: list[ArtifactType]
    requires_key: bool = False
    is_active: bool = False  # True = soumet l'artefact à un service tiers

    def is_configured(self) -> bool:
        return True

    @abstractmethod
    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        ...

    def supports(self, artifact_type: ArtifactType) -> bool:
        return artifact_type in self.supported_types
