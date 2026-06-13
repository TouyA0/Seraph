import asyncio

from app.core.connector import ConnectorResult
from app.core.detector import ArtifactType
from app.core.registry import get_connectors


async def investigate(artifact: str, artifact_type: ArtifactType) -> list[ConnectorResult]:
    connectors = get_connectors(artifact_type)
    if not connectors:
        return []
    tasks = [c.enrich(artifact, artifact_type) for c in connectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out: list[ConnectorResult] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            out.append(ConnectorResult(
                connector=connectors[i].name,
                status="error",
                artifact=artifact,
                artifact_type=artifact_type,
                error=str(result),
            ))
        else:
            out.append(result)
    return out
