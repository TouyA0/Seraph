import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://api.shodan.io"


class ShodanConnector(BaseConnector):
    name = "shodan"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN]
    requires_key = True
    is_active = False

    def is_configured(self) -> bool:
        return bool(os.getenv("SHODAN_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        key = os.getenv("SHODAN_API_KEY", "")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                if artifact_type == ArtifactType.IP:
                    r = await client.get(f"{_BASE}/shodan/host/{artifact}", params={"key": key})
                else:
                    r = await client.get(f"{_BASE}/dns/domain/{artifact}", params={"key": key})
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ConnectorResult(connector=self.name, status="ok",
                                       artifact=artifact, artifact_type=artifact_type,
                                       raw={}, findings=[],
                                       latency_ms=int((time.monotonic() - t0) * 1000))
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []

        if artifact_type == ArtifactType.IP:
            ports = data.get("ports", [])
            if ports:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.EXPOSURE,
                    label=f"{len(ports)} port(s) Shodan : {', '.join(str(p) for p in ports[:10])}",
                    source=self.name,
                ))
            vulns = list(data.get("vulns", {}).keys())
            if vulns:
                sev = Severity.CRITICAL if len(vulns) > 5 else Severity.HIGH
                findings.append(Finding(
                    severity=sev,
                    category=FindingCategory.VULNERABILITY,
                    label=f"{len(vulns)} CVE(s) Shodan : {', '.join(vulns[:5])}",
                    source=self.name,
                    evidence=str(vulns),
                ))
            tags = data.get("tags", [])
            if tags:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=FindingCategory.REPUTATION,
                    label=f"Tags Shodan : {', '.join(tags)}",
                    source=self.name,
                ))
            org = data.get("org", "") or data.get("isp", "")
            country = data.get("country_name", "")
            if org:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.NETWORK,
                    label=f"Organisation : {org} ({country})",
                    source=self.name,
                ))
        else:
            subdomains = data.get("subdomains", [])
            if subdomains:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.EXPOSURE,
                    label=f"{len(subdomains)} sous-domaine(s) Shodan : {', '.join(subdomains[:6])}",
                    source=self.name,
                    evidence=str(subdomains),
                ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw=data, findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
