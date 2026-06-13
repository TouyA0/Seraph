from fastapi import APIRouter
from pydantic import BaseModel

from app.core.detector import ArtifactType, detect, detect_all

router = APIRouter()


class DetectRequest(BaseModel):
    value: str


class DetectResponse(BaseModel):
    value: str
    type: ArtifactType
    candidates: list[ArtifactType]


@router.post("/detect", response_model=DetectResponse)
async def detect_artifact(req: DetectRequest):
    candidates = detect_all(req.value.strip())
    return DetectResponse(
        value=req.value.strip(),
        type=candidates[0],
        candidates=candidates,
    )
