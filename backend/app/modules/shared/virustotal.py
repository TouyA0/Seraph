import os
import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://www.virustotal.com/api/v3"

_TYPE_PATH = {
    ArtifactType.IP: "ip_addresses",
    ArtifactType.DOMAIN: "domains",
    ArtifactType.URL: "urls",
    ArtifactType.HASH: "files",
}


class VirusTotalConnector(BaseConnector):
    name = "virustotal"
    supported_types = [ArtifactType.IP, ArtifactType.DOMAIN, ArtifactType.URL, ArtifactType.HASH]
    requires_key = True
    is_active = False  # consultation uniquement (pas de soumission)

    def is_configured(self) -> bool:
        return bool(os.getenv("VIRUSTOTAL_API_KEY"))

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        path = _TYPE_PATH.get(artifact_type)
        if not path:
            return ConnectorResult(connector=self.name, status="skipped",
                                   artifact=artifact, artifact_type=artifact_type)

        # Pour les URL, VT attend l'ID base64url sans padding
        import base64
        lookup = artifact
        if artifact_type == ArtifactType.URL:
            lookup = base64.urlsafe_b64encode(artifact.encode()).decode().rstrip("=")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"{_BASE}/{path}/{lookup}",
                    headers={"x-apikey": api_key},
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ConnectorResult(connector=self.name, status="error",
                                   artifact=artifact, artifact_type=artifact_type,
                                   error=str(e), latency_ms=int((time.monotonic() - t0) * 1000))

        findings: list[Finding] = []
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if malicious > 0:
            sev = Severity.CRITICAL if malicious >= 10 else Severity.HIGH if malicious >= 5 else Severity.MEDIUM
            findings.append(Finding(
                severity=sev,
                category=FindingCategory.REPUTATION,
                label=f"VirusTotal : {malicious}/{total} moteurs détectent comme malveillant",
                source=self.name,
                evidence=str(stats),
            ))
        elif suspicious > 0:
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.REPUTATION,
                label=f"VirusTotal : {suspicious}/{total} moteurs suspects",
                source=self.name,
                evidence=str(stats),
            ))
        elif total > 0:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.REPUTATION,
                label=f"VirusTotal : 0/{total} détection — propre",
                source=self.name,
            ))

        attrs = data.get("data", {}).get("attributes", {})
        # Catégories (domaine/IP)
        categories = attrs.get("categories", {})
        if categories:
            vals = list(set(categories.values()))[:4]
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.REPUTATION,
                label=f"Catégories : {', '.join(vals)}",
                source=self.name,
            ))

        # Famille malware (hash)
        family = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        if family:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=FindingCategory.BEHAVIOR,
                label=f"Famille malware : {family}",
                source=self.name,
            ))

        return ConnectorResult(connector=self.name, status="ok",
                               artifact=artifact, artifact_type=artifact_type,
                               raw=data.get("data", {}).get("attributes", {}),
                               findings=findings,
                               latency_ms=int((time.monotonic() - t0) * 1000))
