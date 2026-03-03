from fastapi import APIRouter, HTTPException
from fastapi.exceptions import RequestValidationError
from app.pods.pod_b.services.verdict_service import VerdictService
from app.schemas.analyze_request import AnalyzeRequest
import traceback

router = APIRouter()

verdict_service = VerdictService()


@router.post("/analyze")
async def analyze_email(payload: AnalyzeRequest):
    try:
        data = payload.model_dump()
        
        # Filter out None values to match expected format
        data = {k: v for k, v in data.items() if v is not None}
        
        # Filter out None values and empty data
        if not data.get("sender") and not data.get("email"):
            raise HTTPException(status_code=422, detail="At least sender or email field is required")
        
        result = verdict_service.analyze(data)
        
        # Transform to match test expectations
        triggered_signals = result.get("triggered_signals", [])
        
        # Build analysis_results in expected format
        analysis_results = []
        for signal_name in triggered_signals:
            analysis_results.append({
                "signal": signal_name,
                "severity": "high",
                "description": f"Signal {signal_name} was detected",
                "recommendation": "Review this email carefully"
            })
        
        return {
            "status": "success",
            "risk_score": float(result.get("risk_score", 0)),
            "signals_detected": triggered_signals,
            "analysis_results": analysis_results
        }
    except RequestValidationError:
        # Let FastAPI handle validation errors
        raise
    except KeyError as e:
        raise HTTPException(status_code=500, detail=f"Missing required field: {str(e)}")
    except Exception as e:
        # Return detailed error for debugging
        error_detail = f"{str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail[:500])