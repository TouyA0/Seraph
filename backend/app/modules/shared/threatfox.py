import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

import os

_BASE = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxConnector(BaseConnector):
    name = "threatfox"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN, ArtifactType.URL, ArtifactType.HASH]
    requires_key = True
    is_active = False

    def is_configured(self) -> bool:
        return bool(os.getenv("THREATFOX_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            api_key = os.getenv("THREATFOX_API_KEY", "")
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    _BASE,
                    json={"query": "search_ioc", "search_term": artifact},
                    headers={"Auth-Key": api_key},
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(
                connector=self.name, status="error",
                artifact=artifact, artifact_type=artifact_type,
                error=str(e),
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        findings: list[Finding] = []
        query_status = data.get("query_status", "")

        if query_status == "no_result":
            return ConnectorResult(
                connector=self.name, status="ok",
                artifact=artifact, artifact_type=artifact_type,
                raw=data, findings=[],
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        iocs = data.get("data", []) or []
        for ioc in iocs[:5]:
            malware = ioc.get("malware", "")
            confidence = ioc.get("confidence_level", 0)
            tags = ioc.get("tags") or []
            threat_type = ioc.get("threat_type", "")
            first_seen = ioc.get("first_seen", "")

            sev = Severity.HIGH if confidence >= 75 else Severity.MEDIUM if confidence >= 50 else Severity.LOW
            label = f"ThreatFox : {malware} ({threat_type})"
            if tags:
                label += f" — {', '.join(tags[:3])}"

            findings.append(Finding(
                severity=sev,
                category=FindingCategory.REPUTATION,
                label=label,
                source=self.name,
                evidence=f"Confiance {confidence}% · premier signalement {first_seen}",
            ))

        if not findings and iocs:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.REPUTATION,
                label=f"Présent dans ThreatFox ({len(iocs)} entrée(s))",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
