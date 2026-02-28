from fastapi import APIRouter, HTTPException
from app.pods.pod_b.services.verdict_service import VerdictService
from app.schemas.analyze_request import AnalyzeRequest

router = APIRouter()

verdict_service = VerdictService()


@router.post("/analyze")
async def analyze_email(payload: AnalyzeRequest):
    try:
        result = verdict_service.analyze(payload.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))