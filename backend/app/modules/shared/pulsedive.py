import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://pulsedive.com/api/info.php"

_RISK_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
    "retired": Severity.INFO,
}


class PulsediveConnector(BaseConnector):
    name = "pulsedive"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN, ArtifactType.URL]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(_BASE, params={"indicator": artifact, "pretty": "1"})
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(
                connector=self.name, status="error",
                artifact=artifact, artifact_type=artifact_type,
                error=str(e),
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        if "error" in data:
            return ConnectorResult(
                connector=self.name, status="ok",
                artifact=artifact, artifact_type=artifact_type,
                raw=data, findings=[],
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        findings: list[Finding] = []
        risk = data.get("risk", "unknown")
        sev = _RISK_SEV.get(risk, Severity.INFO)

        if risk not in ("none", "unknown", "retired"):
            findings.append(Finding(
                severity=sev,
                category=FindingCategory.REPUTATION,
                label=f"Pulsedive — risque {risk.upper()}",
                source=self.name,
                evidence=f"Score : {data.get('riskfactors', '')}",
            ))

        threats = data.get("threats", []) or []
        if threats:
            names = [t.get("name", "") for t in threats[:3]]
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.REPUTATION,
                label=f"Menaces associées : {', '.join(names)}",
                source=self.name,
            ))

        feeds = data.get("feeds", []) or []
        if feeds:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.REPUTATION,
                label=f"Présent dans {len(feeds)} threat feed(s)",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
