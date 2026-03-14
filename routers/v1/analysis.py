from fastapi import APIRouter, Request

from src.schemas.analysis import AnalyzeTextRequest, AnalysisResult

analysis_router = APIRouter(prefix="/analysis", tags=["analysis"])


@analysis_router.post("/check", response_model=AnalysisResult)
async def analyze_text(payload: AnalyzeTextRequest, request: Request) -> AnalysisResult:
    analysis_service = request.app.state.analysis_service
    return await analysis_service.analyze_text(payload.text)