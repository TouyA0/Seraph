import asyncio

from app.core.connector import ConnectorResult
from app.core.detector import ArtifactType
from app.core.registry import get_connectors, get_all_connectors
from app.services.cache import get_cached, set_cached


async def _run_with_cache(connector, artifact: str, artifact_type: ArtifactType) -> ConnectorResult:
    cached = await get_cached(connector.name, artifact)
    if cached:
        result = ConnectorResult(**cached)
        # Signaler que ça vient du cache
        result.status = result.status  # garder le statut
        return result

    result = await connector.enrich(artifact, artifact_type)
    if result.status == "ok":
        await set_cached(connector.name, artifact, result.model_dump())
    return result


async def investigate(artifact: str, artifact_type: ArtifactType) -> list[ConnectorResult]:
    connectors = get_connectors(artifact_type)
    unconfigured = get_all_connectors(artifact_type, only_unconfigured=True)

    tasks = [_run_with_cache(c, artifact, artifact_type) for c in connectors]
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

    # Ajouter les sources non configurées (pour les afficher grisées côté UI)
    for c in unconfigured:
        out.append(ConnectorResult(
            connector=c.name,
            status="unconfigured",
            artifact=artifact,
            artifact_type=artifact_type,
        ))

    return out
