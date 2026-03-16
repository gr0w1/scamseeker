from typing import Optional, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from src.models.analysis_check import AnalysisCheck
from src.repositories.history_repository import HistoryRepository
from src.schemas.analysis import AnalysisResult


class HistoryService:
    def __init__(self, session: AsyncSession):
        self.repo = HistoryRepository(session)

    async def save_check(
        self,
        *,
        user_id: Optional[int],
        source_text: str,
        normalized_text: str | None,
        result: AnalysisResult,
    ) -> AnalysisCheck:
        return await self.repo.create_from_result(
            user_id=user_id,
            source_text=source_text,
            normalized_text=normalized_text,
            result=result,
        )

    async def list_for_user(
        self,
        user_id: int,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[AnalysisCheck]:
        return await self.repo.list_for_user(user_id=user_id, limit=limit, offset=offset)

    async def get_for_user(self, user_id: int, check_id: int) -> Optional[AnalysisCheck]:
        return await self.repo.get_for_user(user_id=user_id, check_id=check_id)
