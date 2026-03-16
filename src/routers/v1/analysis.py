from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.configurations.database import get_async_session
from src.configurations.security import get_current_user_optional
from src.models.user import User
from src.schemas.analysis import AnalyzeTextRequest, AnalysisResult

analysis_router = APIRouter(prefix="/analysis", tags=["analysis"])


@analysis_router.post("/check", response_model=AnalysisResult)
async def analyze_text(
    payload: AnalyzeTextRequest,
    request: Request,
    session: AsyncSession = Depends(get_async_session),
    current_user: User | None = Depends(get_current_user_optional),
) -> AnalysisResult:
    analysis_service = request.app.state.analysis_service
    return await analysis_service.analyze_text(
        payload.text,
        user_id=current_user.id if current_user else None,
        session=session,
    )

