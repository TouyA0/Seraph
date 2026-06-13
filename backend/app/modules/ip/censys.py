import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://search.censys.io/api/v2"


class CensysConnector(BaseConnector):
    name = "censys"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN]
    requires_key = True
    is_active = False

    def is_configured(self) -> bool:
        return bool(os.getenv("CENSYS_API_ID")) and bool(os.getenv("CENSYS_API_SECRET"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        auth = (os.getenv("CENSYS_API_ID", ""), os.getenv("CENSYS_API_SECRET", ""))

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                if artifact_type == ArtifactType.IP:
                    r = await client.get(f"{_BASE}/hosts/{artifact}", auth=auth)
                else:
                    r = await client.get(
                        f"{_BASE}/certificates",
                        params={"q": f"parsed.names: {artifact}", "per_page": 5},
                        auth=auth,
                    )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []

        if artifact_type == ArtifactType.IP:
            host = data.get("result", {})
            services = host.get("services", [])
            if services:
                ports = [f"{s.get('port')}/{s.get('transport_protocol','').lower()}" for s in services[:8]]
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.EXPOSURE,
                    label=f"{len(services)} service(s) exposé(s) : {', '.join(ports)}",
                    source=self.name,
                ))
            for svc in services:
                if svc.get("tls"):
                    cert = svc.get("tls", {}).get("certificates", {}).get("leaf_data", {})
                    names = cert.get("names", [])
                    if names:
                        findings.append(Finding(
                            severity=Severity.INFO,
                            category=FindingCategory.EXPOSURE,
                            label=f"Certificat TLS : {', '.join(names[:4])}",
                            source=self.name,
                        ))
                    break
            labels = host.get("labels", [])
            if labels:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=FindingCategory.REPUTATION,
                    label=f"Labels Censys : {', '.join(labels[:5])}",
                    source=self.name,
                ))
        else:
            hits = data.get("result", {}).get("hits", [])
            if hits:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.EXPOSURE,
                    label=f"{len(hits)} certificat(s) Censys trouvé(s)",
                    source=self.name,
                ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw=data.get("result", {}),
                               findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
