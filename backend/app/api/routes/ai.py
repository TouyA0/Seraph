import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.services import ai
from app.services.ai_report import AIReport, build_chat_context, generate_report
from app.services.database import get_investigation

router = APIRouter()


class ChatRequest(BaseModel):
    investigation_id: str
    messages: list[dict]  # [{"role": "user"|"assistant", "content": "..."}]


class ReportRequest(BaseModel):
    investigation_id: str


@router.get("/ai/status")
async def ai_status():
    available = await ai.is_available()
    return {
        "available": available,
        "model": ai._MODEL,
        "endpoint": ai._OPENAI_URL or ai._OLLAMA_URL,
        "enabled": ai._ENABLED,
    }


@router.post("/ai/report")
async def get_report(req: ReportRequest):
    from app.core.connector import ConnectorResult
    from app.core.detector import ArtifactType

    inv = await get_investigation(req.investigation_id)
    if not inv:
        return {"error": "Investigation non trouvée"}

    results = [ConnectorResult(**r) for r in (inv.get("results") or [])]
    artifact_type = ArtifactType(inv["type"])

    report = await generate_report(inv["artifact"], artifact_type, results)
    if report is None:
        return {"error": "IA non disponible"}
    return report


@router.post("/ai/chat")
async def chat_stream(req: ChatRequest):
    from app.core.connector import ConnectorResult
    from app.core.detector import ArtifactType
    from app.services.ai_report import AIReport

    inv = await get_investigation(req.investigation_id)
    if not inv:
        return {"error": "Investigation non trouvée"}

    results = [ConnectorResult(**r) for r in (inv.get("results") or [])]
    artifact_type = ArtifactType(inv["type"])
    context = build_chat_context(inv["artifact"], artifact_type, results, None)

    system = f"""Tu es un analyste SOC expert. Réponds en français, de manière précise et concise.
Tu travailles sur une investigation en cours. Voici les données disponibles :

{context}

Règle absolue : cite uniquement des faits présents dans les données ci-dessus. Ne fabrique rien."""

    messages = [{"role": "system", "content": system}] + req.messages

    async def event_stream():
        try:
            async for chunk in ai.stream_chat(messages):
                yield f"data: {json.dumps({'content': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
