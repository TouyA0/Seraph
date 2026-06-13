import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType


class RDAPConnector(BaseConnector):
    name = "rdap"
    supported_types = [ArtifactType.DOMAIN, ArtifactType.IP]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        path = "domain" if artifact_type == ArtifactType.DOMAIN else "ip"
        url = f"https://rdap.org/{path}/{artifact}"
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.get(url)
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

        # Registrar / entities
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            name = ""
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        name = item[3]
                        break
            if "registrar" in roles and name:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.NETWORK,
                    label=f"Registrar : {name}",
                    source=self.name,
                ))
            if "registrant" in roles and name:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.NETWORK,
                    label=f"Registrant : {name}",
                    source=self.name,
                ))

        # Dates
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")[:10]
            if action in ("registration", "expiration"):
                findings.append(Finding(
                    severity=Severity.INFO,
                    category=FindingCategory.NETWORK,
                    label=f"{action.capitalize()} : {date}",
                    source=self.name,
                ))

        # Nameservers
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        if nameservers:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"Nameservers : {', '.join(nameservers[:4])}",
                source=self.name,
            ))

        # Status flags
        statuses = data.get("status", [])
        suspicious = [s for s in statuses if "hold" in s or "lock" not in s and "ok" not in s and "active" not in s]
        if suspicious:
            findings.append(Finding(
                severity=Severity.LOW,
                category=FindingCategory.REPUTATION,
                label=f"Statuts RDAP inhabituels : {', '.join(suspicious)}",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
