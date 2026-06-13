import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://urlscan.io/api/v1"


class URLScanConnector(BaseConnector):
    name = "urlscan"
    supported_types = [ArtifactType.URL, ArtifactType.DOMAIN]
    requires_key = True
    is_active = False  # search uniquement, pas de soumission

    def is_configured(self) -> bool:
        return bool(os.getenv("URLSCAN_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        query = f'domain:"{artifact}"' if artifact_type == ArtifactType.DOMAIN else f'page.url:"{artifact}"'
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"{_BASE}/search/",
                    params={"q": query, "size": 10},
                    headers={"API-Key": os.getenv("URLSCAN_API_KEY", "")},
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []
        results = data.get("results", [])
        total = data.get("total", 0)

        if total == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.REPUTATION,
                label="URLScan : aucun scan trouvé",
                source=self.name,
            ))
        else:
            malicious = [r for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious")]
            if malicious:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.REPUTATION,
                    label=f"URLScan : {len(malicious)}/{len(results)} scan(s) marqué(s) malveillant",
                    source=self.name,
                    evidence=malicious[0].get("page", {}).get("url", "")[:100],
                ))

            # Technologies détectées
            techs: set[str] = set()
            for res in results[:3]:
                for tech in (res.get("page", {}).get("tech") or []):
                    techs.add(tech.get("name", ""))
            if techs:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.EXPOSURE,
                    label=f"Technologies détectées : {', '.join(sorted(techs)[:6])}",
                    source=self.name,
                ))

            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.EXPOSURE,
                label=f"{total} scan(s) URLScan — dernier : {results[0].get('task', {}).get('time', '')[:10]}",
                source=self.name,
            ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw={"total": total, "results": results[:3]},
                               findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
