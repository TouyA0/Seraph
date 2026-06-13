import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://otx.alienvault.com/api/v1"

_SECTION_MAP = {
    ArtifactType.IP: ("IPv4", ["general", "reputation", "malware"]),
    ArtifactType.DOMAIN: ("domain", ["general", "malware", "whois"]),
    ArtifactType.URL: ("url", ["general"]),
    ArtifactType.HASH: ("file", ["general", "analysis"]),
}


class OTXConnector(BaseConnector):
    name = "otx"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN, ArtifactType.URL, ArtifactType.HASH]
    requires_key = True
    is_active = False

    def is_configured(self) -> bool:
        return bool(os.getenv("OTX_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        mapping = _SECTION_MAP.get(artifact_type)
        if not mapping:
            return ConnectorResult(connector=self.name, status="skipped",
                                   artifact=artifact, artifact_type=artifact_type)
        ioc_type, sections = mapping

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                headers = {"X-OTX-API-KEY": os.getenv("OTX_API_KEY", "")}
                r = await client.get(
                    f"{_BASE}/indicators/{ioc_type}/{artifact}/general",
                    headers=headers,
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []
        pulse_count = data.get("pulse_info", {}).get("count", 0)

        if pulse_count > 0:
            pulses = data.get("pulse_info", {}).get("pulses", [])[:3]
            names = [p.get("name", "") for p in pulses]
            sev = Severity.HIGH if pulse_count >= 5 else Severity.MEDIUM if pulse_count >= 2 else Severity.LOW
            findings.append(Finding(
                severity=sev,
                category=FindingCategory.REPUTATION,
                label=f"OTX : présent dans {pulse_count} pulse(s)",
                source=self.name,
                evidence=", ".join(names),
            ))

        tags = data.get("pulse_info", {}).get("related", {}).get("alienvault", {}).get("malware_families", [])
        if tags:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.REPUTATION,
                label=f"Familles malware OTX : {', '.join(tags[:5])}",
                source=self.name,
            ))

        reputation = data.get("reputation", 0)
        if reputation and reputation < -1:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.REPUTATION,
                label=f"Score de réputation OTX : {reputation}",
                source=self.name,
            ))

        if not findings:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.REPUTATION,
                label="OTX : aucun pulse associé",
                source=self.name,
            ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw={"pulse_count": pulse_count, "reputation": reputation},
                               findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
