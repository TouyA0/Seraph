import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://internetdb.shodan.io"


class InternetDBConnector(BaseConnector):
    name = "shodan_internetdb"
    supported_types = [ArtifactType.IP]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{_BASE}/{artifact}")
                if r.status_code == 404:
                    return ConnectorResult(
                        connector=self.name, status="ok",
                        artifact=artifact, artifact_type=artifact_type,
                        raw={}, findings=[],
                        latency_ms=int((time.monotonic() - t0) * 1000),
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

        ports: list[int] = data.get("ports", [])
        if ports:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.EXPOSURE,
                label=f"{len(ports)} port(s) ouverts : {', '.join(str(p) for p in ports[:10])}",
                source=self.name,
                evidence=str(ports),
            ))

        vulns: list[str] = data.get("vulns", [])
        if vulns:
            sev = Severity.HIGH if len(vulns) > 3 else Severity.MEDIUM
            findings.append(Finding(
                severity=sev,
                category=FindingCategory.VULNERABILITY,
                label=f"{len(vulns)} CVE(s) associée(s) : {', '.join(vulns[:5])}",
                source=self.name,
                evidence=str(vulns),
            ))

        tags: list[str] = data.get("tags", [])
        if tags:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=FindingCategory.REPUTATION,
                label=f"Tags Shodan : {', '.join(tags)}",
                source=self.name,
                evidence=str(tags),
            ))

        hostnames: list[str] = data.get("hostnames", [])
        if hostnames:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"Hostnames : {', '.join(hostnames[:5])}",
                source=self.name,
                evidence=str(hostnames),
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
