import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

# ip-api.com — gratuit, sans clé, 45 req/min
_BASE = "http://ip-api.com/json"


class IPApiConnector(BaseConnector):
    name = "ip_api"
    supported_types = [ArtifactType.IP]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{_BASE}/{artifact}",
                    params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
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

        if data.get("status") == "fail":
            return ConnectorResult(
                connector=self.name, status="ok",
                artifact=artifact, artifact_type=artifact_type,
                raw=data, findings=[],
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        findings: list[Finding] = []

        asn = data.get("as", "")
        org = data.get("org", "") or data.get("isp", "")
        country = data.get("country", "")
        city = data.get("city", "")
        region = data.get("regionName", "")

        if asn or org:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"{asn} · {org}",
                source=self.name,
                evidence=f"{city}, {region}, {country}",
            ))

        if data.get("proxy"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.REPUTATION,
                label="Proxy / VPN détecté",
                source=self.name,
            ))

        if data.get("hosting"):
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.REPUTATION,
                label="IP d'hébergement / datacenter",
                source=self.name,
            ))

        reverse = data.get("reverse", "")
        if reverse:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"Reverse DNS : {reverse}",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
