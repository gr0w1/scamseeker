from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.analysis_check import AnalysisCheck
from src.schemas.analysis import AnalysisResult


class HistoryRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_from_result(
        self,
        *,
        user_id: Optional[int],
        source_text: str,
        normalized_text: str | None,
        result: AnalysisResult,
    ) -> AnalysisCheck:
        item = AnalysisCheck(
            user_id=user_id,
            source_text=source_text,
            normalized_text=normalized_text,
            ml_score=result.ml_score,
            rule_score=result.rule_score,
            final_score=result.final_score,
            risk_level=result.risk_level,
            dominant_category=result.dominant_category,
            short_explanation=result.short_explanation,
            reasons=[r.model_dump() for r in result.reasons],
            highlights=[h.model_dump() for h in result.highlights],
            recommendations=result.recommendations,
            category_breakdown=result.category_breakdown,
            model_version=result.model_version,
        )
        self.session.add(item)
        await self.session.flush()
        await self.session.refresh(item)
        return item

    async def list_for_user(
        self,
        user_id: int,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[AnalysisCheck]:
        stmt = (
            select(AnalysisCheck)
            .where(AnalysisCheck.user_id == user_id)
            .order_by(AnalysisCheck.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_for_user(self, user_id: int, check_id: int) -> Optional[AnalysisCheck]:
        stmt = select(AnalysisCheck).where(
            AnalysisCheck.id == check_id,
            AnalysisCheck.user_id == user_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
