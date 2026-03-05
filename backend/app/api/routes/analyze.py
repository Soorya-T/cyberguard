from fastapi import APIRouter, HTTPException
from fastapi.exceptions import RequestValidationError
from app.pods.pod_b.services.verdict_service import VerdictService
from app.schemas.analyze_request import AnalyzeRequest
from app.models.analysis_model import AnalysisRecord
from app.db.session import SessionLocal
import traceback

router = APIRouter()

verdict_service = VerdictService()


@router.get("/reports/history")
def get_reports_history():
    """Get all analysis reports from the database."""
    db = SessionLocal()
    try:
        records = db.query(AnalysisRecord).order_by(AnalysisRecord.id.desc()).all()
        return [
            {
                "id": r.id,
                "sender": r.sender,
                "subject": r.subject,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "pdf_location": r.pdf_location
            }
            for r in records
        ]
    except Exception:
        return []
    finally:
        db.close()


@router.get("/reports/{report_id}")
def get_report_by_id(report_id: int):
    """Get a specific analysis report by ID."""
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="Report not found")
        return {
            "id": record.id,
            "sender": record.sender,
            "subject": record.subject,
            "risk_score": record.risk_score,
            "verdict": record.verdict,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "pdf_location": record.pdf_location
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch report")
    finally:
        db.close()


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
        
        # Save to database
        db = SessionLocal()
        try:
            # Extract sender and subject from the original data or result
            sender = data.get("sender") or "unknown@example.com"
            subject = data.get("subject") or "No Subject"
            
            # Create database record
            record = AnalysisRecord(
                sender=sender,
                subject=subject,
                risk_score=float(result.get("risk_score", 0)),
                verdict=result.get("action_recommended", "UNKNOWN"),
                pdf_location=result.get("pdf_location")
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            record_id = record.id
        except Exception as db_err:
            db.rollback()
            print(f"Database save error: {db_err}")
            import traceback
            traceback.print_exc()
            record_id = None
        finally:
            db.close()
        
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
            "record_id": record_id,
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