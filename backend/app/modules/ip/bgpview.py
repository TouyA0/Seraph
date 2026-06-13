import time

import httpx

from app.core.connector import BaseConnector, ConnectorResult, Finding, FindingCategory, Severity
from app.core.detector import ArtifactType

_BASE = "https://api.bgpview.io"


class BGPViewIPConnector(BaseConnector):
    name = "bgpview_ip"
    supported_types = [ArtifactType.IP]
    requires_key = False
    is_active = False

    async def enrich(self, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{_BASE}/ip/{artifact}")
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
        ip_data = data.get("data", {})

        prefixes = ip_data.get("prefixes", [])
        for prefix in prefixes[:3]:
            asn_info = prefix.get("asn", {})
            asn = asn_info.get("asn")
            name = asn_info.get("name", "")
            description = asn_info.get("description", "")
            prefix_str = prefix.get("prefix", "")
            country = prefix.get("country_code", "")
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"AS{asn} · {name} ({country}) — {prefix_str}",
                source=self.name,
                evidence=description,
            ))

        rir_alloc = ip_data.get("rir_allocation", {})
        if rir_alloc:
            rir = rir_alloc.get("rir_name", "")
            alloc_prefix = rir_alloc.get("prefix", "")
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"Allocation RIR : {rir} — {alloc_prefix}",
                source=self.name,
                evidence=str(rir_alloc),
            ))

        ptr = ip_data.get("ptr_record")
        if ptr:
            findings.append(Finding(
                severity=Severity.INFO,
                category=FindingCategory.NETWORK,
                label=f"PTR : {ptr}",
                source=self.name,
            ))

        return ConnectorResult(
            connector=self.name, status="ok",
            artifact=artifact, artifact_type=artifact_type,
            raw=data, findings=findings,
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
