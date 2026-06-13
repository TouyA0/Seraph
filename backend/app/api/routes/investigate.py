import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.detector import ArtifactType, detect, detect_all
from app.core.orchestrator import investigate
from app.core.connector import ConnectorResult
from app.services.database import save_investigation, list_investigations, get_investigation

router = APIRouter()


class DetectRequest(BaseModel):
    value: str


class DetectResponse(BaseModel):
    value: str
    type: ArtifactType
    candidates: list[ArtifactType]


class InvestigateRequest(BaseModel):
    value: str
    type: ArtifactType | None = None


class InvestigateResponse(BaseModel):
    id: str
    artifact: str
    type: ArtifactType
    results: list[ConnectorResult]
    total_findings: int
    ai_report: dict | None = None


@router.post("/detect", response_model=DetectResponse)
async def detect_artifact(req: DetectRequest):
    candidates = detect_all(req.value.strip())
    return DetectResponse(
        value=req.value.strip(),
        type=candidates[0],
        candidates=candidates,
    )


@router.post("/investigate", response_model=InvestigateResponse)
async def run_investigation(req: InvestigateRequest):
    artifact = req.value.strip()
    artifact_type = req.type or detect(artifact)

    if artifact_type == ArtifactType.UNKNOWN:
        raise HTTPException(status_code=422, detail="Type d'artefact non reconnu.")

    results = await investigate(artifact, artifact_type)
    inv_id = str(uuid.uuid4())

    results_dicts = [r.model_dump() for r in results]
    await save_investigation(inv_id, artifact, artifact_type.value, results_dicts)

    total_findings = sum(len(r.findings) for r in results)
    return InvestigateResponse(
        id=inv_id,
        artifact=artifact,
        type=artifact_type,
        results=results,
        total_findings=total_findings,
        ai_report=None,
    )


@router.get("/investigations")
async def get_investigations():
    return await list_investigations()


@router.get("/investigations/{inv_id}")
async def get_investigation_by_id(inv_id: str):
    inv = await get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation non trouvée.")
    return inv
