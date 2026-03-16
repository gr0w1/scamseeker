from abc import ABC, abstractmethod
from typing import Optional, Sequence

from src.models.analysis_check import AnalysisCheck
from src.schemas.analysis import AnalysisResult


class BaseAnalysisCheckRepository(ABC):
    @abstractmethod
    async def create(
        self,
        *,
        user_id: Optional[int],
        source_text: str,
        normalized_text: Optional[str],
        result: AnalysisResult,
    ) -> AnalysisCheck:
        raise NotImplementedError

    @abstractmethod
    async def get_by_id(self, check_id: int, user_id: Optional[int] = None) -> Optional[AnalysisCheck]:
        raise NotImplementedError

    @abstractmethod
    async def list_by_user(self, user_id: int, limit: int = 20, offset: int = 0) -> Sequence[AnalysisCheck]:
        raise NotImplementedError