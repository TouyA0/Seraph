import json
import re

from pydantic import BaseModel

from app.core.connector import ConnectorResult
from app.core.detector import ArtifactType
from app.services import ai


class AIReport(BaseModel):
    summary: str
    score: int  # 0-10, 0=bénin 10=critique
    score_rationale: str
    recommendation: str  # "bloquer" | "surveiller" | "ignorer" | "approfondir"
    contradictions: list[str] = []


_SYSTEM_PROMPT = """Tu es un analyste SOC expert en threat intelligence. Tu analyses des résultats d'investigation sur des artefacts (IP, domaines, hachages, URLs).

Règles absolues :
- Tu ne cites QUE des faits présents dans les données fournies. Jamais d'invention.
- Chaque affirmation doit être attribuée à la source qui l'a produite (ex: "selon Pulsedive", "d'après Shodan InternetDB").
- Si les sources se contredisent, signale-le explicitement dans "contradictions".
- Le score de menace est de 0 (bénin certain) à 10 (malveillant confirmé).
- Réponds UNIQUEMENT en JSON valide, sans markdown, sans texte avant ou après."""

_REPORT_PROMPT = """Voici les résultats d'investigation pour l'artefact : {artifact} (type : {artifact_type})

{findings_text}

Produis un rapport JSON avec exactement ces champs :
{{
  "summary": "Résumé exécutif en 2-3 phrases, en français, citant les sources",
  "score": <entier 0-10>,
  "score_rationale": "Justification du score en 1 phrase",
  "recommendation": "<bloquer|surveiller|ignorer|approfondir>",
  "contradictions": ["<contradiction 1 si existe>", ...]
}}"""


def _format_findings(results: list[ConnectorResult]) -> str:
    lines: list[str] = []
    for r in results:
        if r.status not in ("ok",) or not r.findings:
            continue
        lines.append(f"\n[{r.connector}]")
        for f in r.findings:
            evidence = f" — {f.evidence}" if f.evidence else ""
            lines.append(f"  [{f.severity.upper()}] {f.label}{evidence}")
    if not lines:
        return "Aucun finding significatif collecté."
    return "\n".join(lines)


def _parse_json_response(text: str) -> dict:
    # Extraire le JSON même si entouré de texte
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError(f"Pas de JSON valide dans la réponse : {text[:200]}")


async def generate_report(
    artifact: str,
    artifact_type: ArtifactType,
    results: list[ConnectorResult],
) -> AIReport | None:
    if not await ai.is_available():
        return None

    findings_text = _format_findings(results)
    prompt = _REPORT_PROMPT.format(
        artifact=artifact,
        artifact_type=artifact_type.value,
        findings_text=findings_text,
    )

    try:
        response = await ai.chat([
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ])
        data = _parse_json_response(response)
        return AIReport(
            summary=data.get("summary", ""),
            score=max(0, min(10, int(data.get("score", 0)))),
            score_rationale=data.get("score_rationale", ""),
            recommendation=data.get("recommendation", "approfondir"),
            contradictions=data.get("contradictions", []),
        )
    except Exception as e:
        return AIReport(
            summary=f"Erreur de génération IA : {e}",
            score=0,
            score_rationale="",
            recommendation="approfondir",
        )


def build_chat_context(
    artifact: str,
    artifact_type: ArtifactType,
    results: list[ConnectorResult],
    ai_report: AIReport | None,
) -> str:
    findings_text = _format_findings(results)
    ctx = f"Artefact investigué : {artifact} (type : {artifact_type.value})\n\n"
    ctx += f"Findings collectés :\n{findings_text}\n"
    if ai_report:
        ctx += f"\nRapport IA :\n"
        ctx += f"Score : {ai_report.score}/10 — {ai_report.score_rationale}\n"
        ctx += f"Recommandation : {ai_report.recommendation}\n"
        ctx += f"Synthèse : {ai_report.summary}\n"
    return ctx
