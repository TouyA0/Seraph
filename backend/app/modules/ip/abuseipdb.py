import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBConnector(BaseConnector):
    name = "abuseipdb"
    supported_types = [ArtifactType.IP]
    requires_key = True
    is_active = False

    def is_configured(self) -> bool:
        return bool(os.getenv("ABUSEIPDB_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{_BASE}/check",
                    params={"ipAddress": artifact, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": os.getenv("ABUSEIPDB_API_KEY", ""), "Accept": "application/json"},
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        country = d.get("countryCode", "")
        isp = d.get("isp", "")
        usage = d.get("usageType", "")

        if score >= 80:
            sev = Severity.CRITICAL
        elif score >= 50:
            sev = Severity.HIGH
        elif score >= 20:
            sev = Severity.MEDIUM
        elif score > 0:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        findings.append(Finding(
            severity=sev,
            category=FindingCategory.REPUTATION,
            label=f"AbuseIPDB : score {score}/100 — {reports} signalement(s)",
            source=self.name,
            evidence=f"{isp} · {usage} · {country}",
        ))

        categories_raw = []
        for report in (d.get("reports") or [])[:5]:
            for cat in (report.get("categories") or []):
                categories_raw.append(str(cat))
        if categories_raw:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.REPUTATION,
                label=f"Types d'abus signalés : {', '.join(set(categories_raw))}",
                source=self.name,
            ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw=d, findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
