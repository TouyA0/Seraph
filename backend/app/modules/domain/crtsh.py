import time
from collections import Counter

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType


class CrtShConnector(BaseConnector):
    name = "crtsh"
    supported_types = [ArtifactType.DOMAIN]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{artifact}", "output": "json"},
                    headers={"Accept": "application/json"},
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
        if not data:
            return ConnectorResult(
                connector=self.name, status="ok",
                artifact=artifact, artifact_type=artifact_type,
                raw={}, findings=[],
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # Unique subdomains
        subdomains: set[str] = set()
        issuers: list[str] = []
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub != artifact:
                    subdomains.add(sub)
            issuer = entry.get("issuer_name", "")
            if issuer:
                issuers.append(issuer)

        if subdomains:
            sample = sorted(subdomains)[:8]
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.EXPOSURE,
                label=f"{len(subdomains)} sous-domaine(s) dans CT logs : {', '.join(sample)}{'…' if len(subdomains) > 8 else ''}",
                source=self.name,
                evidence=str(sorted(subdomains)),
            ))

        # Issuer diversity
        top_issuers = Counter(issuers).most_common(3)
        if top_issuers:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.EXPOSURE,
                label=f"{len(data)} certificat(s) émis · principaux CA : {', '.join(i[0][:40] for i in top_issuers)}",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw={"count": len(data), "subdomains": sorted(subdomains)},
            findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
