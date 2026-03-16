from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.configurations.database import get_async_session
from src.configurations.security import get_current_user
from src.models.user import User
from src.schemas.history import HistoryListItem, HistoryDetail
from src.services.history import HistoryService


history_router = APIRouter(prefix="/history", tags=["history"])


@history_router.get("/", response_model=list[HistoryListItem])
async def list_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[HistoryListItem]:
    service = HistoryService(session)
    items = await service.list_for_user(current_user.id, limit=limit, offset=offset)

    return [
        HistoryListItem(
            id=item.id,
            created_at=item.created_at,
            risk_level=item.risk_level,
            final_score=item.final_score,
            short_explanation=item.short_explanation or "",
        )
        for item in items
    ]


@history_router.get("/{check_id}", response_model=HistoryDetail)
async def get_history_item(
    check_id: int,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> HistoryDetail:
    service = HistoryService(session)
    item = await service.get_for_user(current_user.id, check_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запись не найдена",
        )

    return HistoryDetail(
        id=item.id,
        created_at=item.created_at,
        text=item.source_text,
        normalized_text=item.normalized_text,
        ml_score=item.ml_score,
        rule_score=item.rule_score,
        final_score=item.final_score,
        risk_level=item.risk_level,
        dominant_category=item.dominant_category,
        short_explanation=item.short_explanation or "",
        recommendations=item.recommendations,
        reasons=item.reasons,
        highlights=item.highlights,
        model_highlights=[],
        category_breakdown=item.category_breakdown,
        model_version=item.model_version,
    )
